import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import authConfig from '@config/auth.config';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UserSession } from './entities/user-session.entity';
import { RedisService } from '@modules/redis/services/redis.service';
import { AuthMetadata } from './entities/auth-metadata.entity';
import QueueService from '@modules/email/queue.service';
import { LockoutService } from './lockout.service';
import { SessionService } from './session.service';

const OTP_LENGTH = 6;
const OTP_TTL_SECONDS = 300; // 5 minutes
const OTP_RESEND_COOLDOWN_SECONDS = 30;
const MAX_OTP_ATTEMPTS = 5;

@Injectable()
export default class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly queueService: QueueService,
    private readonly lockoutService: LockoutService,
    private readonly sessionService: SessionService,

    @InjectRepository(UserSession)
    private readonly userSessionRepository: Repository<UserSession>,

    @InjectRepository(AuthMetadata)
    private readonly authMetaData: Repository<AuthMetadata>,

    private readonly dataSource: DataSource,
  ) { }

  async createNewUser(createUserDto: CreateUserDTO) {
    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    let saved: User;

    try {
      const user = queryRunner.manager.create(User, {
        email: createUserDto.email,
        full_name: createUserDto.full_name,
        country: createUserDto.country ?? null,
        password: hashedPassword,
        auth_provider: 'email',
        terms_accepted: createUserDto.terms_accepted,
      });

      saved = await queryRunner.manager.save(user);

      const authMetaData = queryRunner.manager.create(AuthMetadata, {
        user_id: saved.id,
        last_login_at: null,
      });
      await queryRunner.manager.save(authMetaData);

      await queryRunner.commitTransaction();
    } catch (error) {
      await queryRunner.rollbackTransaction();

      const err = error as Error;
      this.logger.error(`Registration failed: ${err.message}`, err.stack);

      let errorMessage = SYS_MSG.SESSION_CREATION_FAILED;
      const statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

      if (err.name === 'QueryFailedError') {
        errorMessage = 'Database error occurred during registration';
        this.logger.error('DB_ERROR during registration', err);
      }

      throw new CustomHttpException(errorMessage, statusCode);
    } finally {
      await queryRunner.release();
    }

    // Issued after commit so a DB rollback does not leave a dangling OTP in Redis or send a spurious email.
    // Failure here is non-fatal — the user was created and can request a resend via /resend-otp.
    try {
      await this.issueOtp(createUserDto.email);
    } catch (otpError) {
      const err = otpError as Error;
      this.logger.error(`OTP dispatch failed after registration: ${err.message}`, err.stack);
    }

    return {
      status_code: HttpStatus.CREATED,
      message: SYS_MSG.USER_CREATED_SUCCESSFULLY,
      data: {
        redirect_url: '/dashboard',
        user: {
          id: saved.id,
          full_name: saved.full_name,
          email: saved.email,
          avatar_url: saved.avatar_url,
        },
      },
    };
  }

  async loginUser(loginDto: LoginDto): Promise<object> {
    const user = await this.userRepository.findOne({ where: { email: loginDto.email } });

    if (!user || !user.password) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const meta = await this.lockoutService.findOrCreate(user.id);

    if (this.lockoutService.isLocked(meta)) {
      throw new CustomHttpException(
        SYS_MSG.ACCOUNT_LOCKED_SECONDS(this.lockoutService.secondsRemaining(meta)),
        HttpStatus.FORBIDDEN
      );
    }

    const isMatch = await bcrypt.compare(loginDto.password, user.password);

    if (!isMatch) {
      await this.lockoutService.recordFailure(meta);
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    await this.lockoutService.clear(meta);
    const { rawToken, sessionId } = await this.sessionService.create(user);

    const jwtExpirySeconds = +(authConfig().jwtExpiry ?? 3600);
    const access_token = this.jwtService.sign({ sub: user.id, id: user.id, email: user.email, sid: sessionId });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.LOGIN_SUCCESSFUL,
      data: {
        access_token,
        refresh_token: rawToken,
        expires_at: new Date(Date.now() + jwtExpirySeconds * 1000).toISOString(),
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          avatar_url: user.avatar_url,
        },
      },
    };
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    if (!user.password || !(await bcrypt.compare(oldPassword, user.password))) {
      throw new CustomHttpException(SYS_MSG.INVALID_PASSWORD, HttpStatus.BAD_REQUEST);
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await this.userRepository.save(user);

    return { status_code: HttpStatus.OK, message: SYS_MSG.PASSWORD_UPDATED };
  }

  async sendOtp(email: string) {
    if (await this.redisService.exists(`limit:${email}`)) {
      throw new CustomHttpException(SYS_MSG.OTP_COOLDOWN, HttpStatus.TOO_MANY_REQUESTS);
    }

    const user = await this.userRepository.findOne({ where: { email } });
    // Silently succeed for unknown emails — prevents account enumeration
    if (!user) return { status_code: HttpStatus.OK, message: SYS_MSG.OTP_SENT };

    await this.issueOtp(email);
    return { status_code: HttpStatus.OK, message: SYS_MSG.OTP_SENT };
  }

  async verifyOtp(email: string, otp: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.INVALID_OTP, HttpStatus.BAD_REQUEST);
    }

    // Check OTP existence before burning an attempt — expired OTPs should not penalise the user
    const hashedOtp = await this.redisService.get(`otp:${email}`);
    if (!hashedOtp) {
      throw new CustomHttpException(SYS_MSG.OTP_EXPIRED, HttpStatus.BAD_REQUEST);
    }

    const attemptsKey = `attempts:${email}`;
    const attempts = await this.redisService.incr(attemptsKey);
    if (attempts === 1) {
      // Use expire (not set) to avoid resetting the counter value in a race
      await this.redisService.expire(attemptsKey, OTP_TTL_SECONDS);
    }
    if ((attempts ?? 0) > MAX_OTP_ATTEMPTS) {
      throw new CustomHttpException(SYS_MSG.TOO_MANY_OTP_ATTEMPTS, HttpStatus.TOO_MANY_REQUESTS);
    }

    const isMatch = await bcrypt.compare(otp, hashedOtp);
    if (!isMatch) {
      throw new CustomHttpException(SYS_MSG.INVALID_OTP, HttpStatus.BAD_REQUEST);
    }

    try {
      user.is_verified = true;
      user.otp_code = null;
      user.expires_at = null;
      await this.userRepository.save(user);
    } catch (error) {
      const err = error as Error;
      this.logger.error(`OTP verification failed: ${err.message}`, err.stack);
      throw new CustomHttpException(SYS_MSG.SESSION_CREATION_FAILED, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    await Promise.all([
      this.redisService.del(`otp:${email}`),
      this.redisService.del(`attempts:${email}`),
      this.redisService.del(`limit:${email}`),
    ]);

    const { rawToken, sessionId } = await this.sessionService.create(user);

    const access_token = this.jwtService.sign({
      id: user.id,
      sub: user.id,
      sid: sessionId,
      email: user.email,
    });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.EMAIL_VERIFIED,
      data: {
        access_token,
        refresh_token: rawToken,
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          avatar_url: user.avatar_url,
          is_verified: true,
        },
      },
    };
  }

  async resendOtp(email: string) {
    if (await this.redisService.exists(`limit:${email}`)) {
      throw new CustomHttpException(SYS_MSG.OTP_COOLDOWN, HttpStatus.TOO_MANY_REQUESTS);
    }

    // Clear stale OTP and attempts so the fresh code starts with a clean slate
    await Promise.all([this.redisService.del(`otp:${email}`), this.redisService.del(`attempts:${email}`)]);

    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) return { status_code: HttpStatus.OK, message: SYS_MSG.OTP_SENT };

    await this.issueOtp(email);
    return { status_code: HttpStatus.OK, message: SYS_MSG.OTP_SENT };
  }

  // Generates a fresh OTP, stores the bcrypt hash in Redis, and queues the email.
  // The plaintext OTP is never persisted to the database.
  private async issueOtp(email: string): Promise<void> {
    const otp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(otp, 10);
    await this.redisService.set(`otp:${email}`, hashedOtp, OTP_TTL_SECONDS);
    await this.redisService.set(`limit:${email}`, '1', OTP_RESEND_COOLDOWN_SECONDS);
    await this.queueService.sendMail({
      variant: 'register-otp',
      mail: { to: email, context: { otp, email } },
    });
  }

  private generateOtp(): string {
    return randomInt(0, 10 ** OTP_LENGTH).toString().padStart(OTP_LENGTH, '0');
  }
}
