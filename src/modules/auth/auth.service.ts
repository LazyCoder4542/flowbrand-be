import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { createHmac, randomInt } from 'crypto';
import authConfig from '@config/auth.config';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { UserSession } from './entities/user-session.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
<<<<<<< BE-003-reset-password-flow
import { RedisService } from '@modules/redis/services/redis.service';
import { randomInt } from 'crypto';
import { EmailService } from '@modules/email/email.service';
import { FRONTEND_RESET_PASSWORD } from '@shared/constants/app-constants';

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;
const RESET_OTP_TTL_SECONDS = 300;
=======
import { UserSession } from './entities/user-session.entity';
import { GoogleOAuthProfile, OAuthLoginResponse } from './dto/google-oauth.dto';
import { v4 as uuidv4 } from 'uuid';
import { RedisService } from '@modules/redis/services/redis.service';
import { AuthMetadata } from './entities/auth-metadata.entity';
import QueueService from '@modules/email/queue.service';
import { LockoutService } from './lockout.service';
import { SessionService } from './session.service';

const OTP_LENGTH = 6;
const OTP_TTL_SECONDS = 300; // 5 minutes
const OTP_RESEND_COOLDOWN_SECONDS = 30;
const MAX_OTP_ATTEMPTS = 5;
>>>>>>> dev

@Injectable()
export default class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
<<<<<<< BE-003-reset-password-flow
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly emailService: EmailService,
    private readonly dataSource: DataSource
  ) {}
=======
    @InjectRepository(UserSession)
    private readonly userSessionRepository: Repository<UserSession>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly queueService: QueueService,
    private readonly lockoutService: LockoutService,
    private readonly sessionService: SessionService,
    @InjectRepository(AuthMetadata)
    private readonly authMetaData: Repository<AuthMetadata>,
    private readonly dataSource: DataSource,
  ) { }
>>>>>>> dev

  async createNewUser(createUserDto: CreateUserDTO) {
    // Normalize email: trim whitespace and convert to lowercase
    // NOTE: This is a workaround until the email column is migrated to PostgreSQL citext
    // for case-insensitive uniqueness enforcement at the database level.
    const email = createUserDto.email.trim().toLowerCase();

    const existing = await this.userRepository.findOne({ where: { email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

<<<<<<< BE-003-reset-password-flow
    const hashedPassword = await this.hashPassword(createUserDto.password);
    const user = this.userRepository.create({
      email: createUserDto.email,
      full_name: createUserDto.full_name,
      country: createUserDto.country ?? null,
      password: hashedPassword,
      auth_provider: 'email',
      otp_code: this.generateOtp(),
      expires_at: this.computeOtpExpiry(),
    });
    const saved = await this.userRepository.save(user);
=======
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
>>>>>>> dev

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

  async loginUser(loginDto: LoginDto) {
    // Normalize email: trim whitespace and convert to lowercase
    // Matches normalization performed during user creation and OAuth login
    const email = loginDto.email.trim().toLowerCase();

    const user = await this.userRepository.findOne({ where: { email } });
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

    user.password = await this.hashPassword(newPassword);
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

  async handleOAuthLogin(profile: GoogleOAuthProfile): Promise<OAuthLoginResponse> {
    const email = profile.email?.trim().toLowerCase();

    if (!email) {
      throw new CustomHttpException(SYS_MSG.GOOGLE_ACCOUNT_NO_EMAIL, HttpStatus.BAD_REQUEST);
    }

    const existing = await this.userRepository.findOne({ where: { email } });
    let user = existing;

    if (user) {
      if (user.auth_provider === 'google' && user.provider_user_id && user.provider_user_id !== profile.providerId) {
        throw new CustomHttpException(SYS_MSG.GOOGLE_ACCOUNT_LINK_CONFLICT, HttpStatus.CONFLICT);
      }

      if (user.auth_provider === 'email' || !user.provider_user_id) {
        user.auth_provider = 'google';
        user.provider_user_id = profile.providerId;
        user.full_name = profile.full_name;
        user.avatar_url = profile.avatar_url;
        user = await this.userRepository.save(user);
      }
    } else {
      user = await this.userRepository.save(
        this.userRepository.create({
          email,
          full_name: profile.full_name,
          avatar_url: profile.avatar_url,
          password: null,
          country: null,
          auth_provider: 'google',
          provider_user_id: profile.providerId,
        })
      );
    }

    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_OAUTH_CREATION_FAILED, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    const rawRefreshToken = uuidv4();
    const hashedRefreshToken = this.hashRefreshToken(rawRefreshToken);
    const refreshExpirySeconds = +(authConfig().jwtRefreshExpiry ?? 604800);
    const expiresAt = new Date(Date.now() + refreshExpirySeconds * 1000);

    const session = await this.userSessionRepository.save(
      this.userSessionRepository.create({
        user_id: user.id,
        refresh_token: hashedRefreshToken,
        expires_at: expiresAt,
        is_revoked: false,
      })
    );

    try {
      await this.redisService.set(`refresh:${session.id}`, hashedRefreshToken, refreshExpirySeconds);
    } catch (error) {
      console.error('Failed to persist OAuth refresh token to Redis', error);
    }

    const access_token = this.jwtService.sign({ id: user.id, sub: user.id, email: user.email, sid: session.id });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.OAUTH_LOGIN_SUCCESSFUL,
      access_token,
      refresh_token: rawRefreshToken,
      data: {
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          avatar_url: user.avatar_url,
        },
      },
    };
  }

<<<<<<< BE-003-reset-password-flow
  async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (user) {
      const otp = this.generateOtp();
      const key = `reset_otp:${email}`;
      try {
        await this.redisService.set(key, otp, RESET_OTP_TTL_SECONDS);
        await this.emailService.sendForgotPasswordMail(email, user.full_name, FRONTEND_RESET_PASSWORD, otp);
      } catch (err) {
        this.logger.error(
          `Failed to issue password reset OTP for user ${user.id}`,
          (err as Error).stack ?? (err as Error).message
        );
      }
    }
    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.FORGOT_PASSWORD_OTP_SENT,
    };
  }

  async resetPassword(email: string, otp: string, newPassword: string) {
    const key = `reset_otp:${email}`;
    const storedOtp = await this.redisService.get(key);

    if (otp !== storedOtp) {
      throw new CustomHttpException(SYS_MSG.INCORRECT_TOTP_CODE, HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      await this.redisService.del(key);
      throw new CustomHttpException(SYS_MSG.INCORRECT_TOTP_CODE, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await this.hashPassword(newPassword);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    try {
      await queryRunner.manager.update(User, { id: user.id }, { password: hashedPassword });
      await queryRunner.manager.update(
        UserSession,
        { user_id: user.id, is_revoked: false },
        { is_revoked: true, revoked_at: new Date() }
      );
      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();
      throw err;
    } finally {
      await queryRunner.release();
    }

    // Redis cleanup is best-effort; the DB is the source of truth.
    // Session cache is purged before the OTP key so a partial failure
    // still leaves the OTP valid for a safe retry.
    try {
      await this.redisService.delByPattern(`active_session:${user.id}:*`);
    } catch (err) {
      this.logger.warn(`Failed to purge session cache for user ${user.id}: ${(err as Error).message}`);
    }

    try {
      await this.redisService.del(key);
    } catch (err) {
      this.logger.warn(`Failed to delete reset OTP key for ${email}: ${(err as Error).message}`);
    }

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.PASSWORD_UPDATED,
    };
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  private generateOtp(length: number = OTP_LENGTH): string {
    if (!Number.isInteger(length) || length < 1 || length > 10) {
      throw new RangeError('OTP length must be an integer between 1 and 10');
    }
    const max = 10 ** length;
    return randomInt(0, max).toString().padStart(length, '0');
=======
  private hashRefreshToken(token: string): string {
    const secret = authConfig().jwtRefreshSecret;

    if (!secret) {
      throw new CustomHttpException(SYS_MSG.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    return createHmac('sha256', secret).update(token).digest('hex');
  }

  private verifyRefreshToken(token: string, hash: string): boolean {
    return this.hashRefreshToken(token) === hash;
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
    return Math.floor(Math.random() * 10 ** OTP_LENGTH)
      .toString()
      .padStart(OTP_LENGTH, '0');
>>>>>>> dev
  }
}
