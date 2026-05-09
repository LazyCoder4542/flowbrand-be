import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UserSession } from './entities/user-session.entity';
import * as crypto from 'crypto';
import { Response } from 'express';
import { RedisService } from '@modules/redis/services/redis.service';
import { AuthMetadata } from './entities/auth-metadata.entity';

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;

@Injectable()
export default class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

    @InjectRepository(UserSession)
    private readonly userSessionRepository: Repository<UserSession>,

    @InjectRepository(AuthMetadata)
    private readonly authMetaData: Repository<AuthMetadata>,

    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly dataSource: DataSource
  ) {}

  async createNewUser(createUserDto: CreateUserDTO, response: Response) {
    if (!createUserDto.terms_accepted) {
      throw new CustomHttpException(SYS_MSG.TERMS_AND_CONDITIONS, HttpStatus.BAD_REQUEST);
    }

    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      if (!existing.is_active) {
        throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_LOCKED, HttpStatus.LOCKED);
      }
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    let saved: User;
    let userSession: UserSession;

    try {
      const user = queryRunner.manager.create(User, {
        email: createUserDto.email,
        full_name: createUserDto.full_name,
        country: createUserDto.country ?? null,
        password: hashedPassword,
        auth_provider: 'email',
        terms_accepted: createUserDto.terms_accepted,
        otp_code: this.generateOtp(),
        expires_at: this.computeOtpExpiry(),
      });
      saved = await queryRunner.manager.save(user);

      userSession = queryRunner.manager.create(UserSession, {
        user_id: saved.id,
        refresh_token: this.generateRefreshToken(),
        expires_at: refreshTokenExpiry,
        is_revoked: false,
      });
      await queryRunner.manager.save(userSession);

      const redisKey = `sess:${saved.id}:${userSession.id}`;
      await this.redisService.set(redisKey, userSession.id, 900);

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

      // Map error types to specific messages
      let errorMessage = SYS_MSG.SESSION_CREATION_FAILED;
      let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

      if (err.name === 'QueryFailedError') {
        errorMessage = 'Database error occurred during registration';
        this.logger.error('DB_ERROR during registration', err);
      } else if (err.message?.includes('Redis') || err.message?.includes('redis')) {
        errorMessage = 'Session storage error occurred';
        this.logger.error('REDIS_ERROR during registration', err);
      }

      throw new CustomHttpException(errorMessage, statusCode);
    } finally {
      await queryRunner.release();
    }

    response.cookie('refresh_token', userSession.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const access_token = this.jwtService.sign({
      id: saved.id,
      sub: saved.id,
      session_id: userSession.id,
      email: saved.email,
    });

    return {
      status_code: HttpStatus.CREATED,
      message: SYS_MSG.USER_CREATED_SUCCESSFULLY,
      access_token,
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
    const user = await this.userRepository.findOne({ where: { email: loginDto.email } });
    if (!user || !user.password) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const isMatch = await bcrypt.compare(loginDto.password, user.password);
    if (!isMatch) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const access_token = this.jwtService.sign({ id: user.id, sub: user.id, email: user.email });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.LOGIN_SUCCESSFUL,
      access_token,
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

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.PASSWORD_UPDATED,
    };
  }

  private generateOtp(): string {
    return Math.floor(Math.random() * 10 ** OTP_LENGTH)
      .toString()
      .padStart(OTP_LENGTH, '0');
  }

  private computeOtpExpiry(): Date {
    return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(40).toString('hex');
  }
}
