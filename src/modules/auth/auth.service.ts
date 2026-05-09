import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UserSession } from './entities/user-session.entity';
import { GoogleOAuthProfile, OAuthLoginResponse } from './dto/google-oauth.dto';
import { v4 as uuidv4 } from 'uuid';
import Redis from 'ioredis';
import authConfig from '@config/auth.config';

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;

@Injectable()
export default class AuthenticationService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserSession)
    private readonly userSessionRepository: Repository<UserSession>,
    private readonly jwtService: JwtService
  ) {}

  async createNewUser(createUserDto: CreateUserDTO) {
    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
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

    const access_token = this.jwtService.sign({ id: saved.id, sub: saved.id, email: saved.email });

    return {
      status_code: HttpStatus.CREATED,
      message: SYS_MSG.USER_CREATED_SUCCESSFULLY,
      access_token,
      data: {
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

  async handleOAuthLogin(payload: GoogleOAuthProfile): Promise<OAuthLoginResponse> {
    const email = payload.email.trim().toLowerCase();
    if (!email) {
      throw new CustomHttpException(SYS_MSG.GOOGLE_ACCOUNT_NO_EMAIL, HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.manager.transaction(async manager => {
      const userRepo = manager.getRepository(User);
      let currentUser = await userRepo.findOne({ where: { email } });

      if (!currentUser) {
        const newUser = userRepo.create({
          email,
          full_name: payload.full_name || email,
          country: null,
          password: null,
          auth_provider: 'google',
          provider_user_id: payload.providerId,
          otp_code: this.generateOtp(),
          expires_at: this.computeOtpExpiry(),
          avatar_url: payload.avatar_url ?? null,
          is_verified: true,
        });

        try {
          currentUser = await userRepo.save(newUser);
        } catch (err: unknown) {
          const error = err as { code?: string };
          if (error.code !== '23505') {
            throw err;
          }

          currentUser = await userRepo.findOne({ where: { email } });
          if (!currentUser) {
            throw new CustomHttpException(SYS_MSG.USER_OAUTH_CREATION_FAILED, HttpStatus.INTERNAL_SERVER_ERROR);
          }
        }
      }

      if (currentUser.auth_provider === 'email') {
        currentUser.auth_provider = 'google';
        currentUser.provider_user_id = payload.providerId;
      } else if (
        currentUser.auth_provider === 'google' &&
        currentUser.provider_user_id &&
        currentUser.provider_user_id !== payload.providerId
      ) {
        throw new CustomHttpException(SYS_MSG.GOOGLE_ACCOUNT_LINK_CONFLICT, HttpStatus.CONFLICT);
      } else if (!currentUser.provider_user_id) {
        currentUser.auth_provider = 'google';
        currentUser.provider_user_id = payload.providerId;
      } else if (currentUser.auth_provider !== 'google') {
        throw new CustomHttpException(SYS_MSG.GOOGLE_ACCOUNT_LINK_CONFLICT, HttpStatus.CONFLICT);
      }

      currentUser.full_name = payload.full_name || currentUser.full_name;
      currentUser.avatar_url = payload.avatar_url ?? currentUser.avatar_url;
      currentUser.is_verified = true;

      return userRepo.save(currentUser);
    });

    const config = authConfig();
    const refreshToken = uuidv4();
    const refreshExpirySeconds = Number(config.jwtRefreshExpiry) || 60 * 60 * 24 * 30;
    const session = this.userSessionRepository.create({
      user_id: user.id,
      refresh_token: refreshToken,
      expires_at: new Date(Date.now() + refreshExpirySeconds * 1000),
      is_revoked: false,
    });

    const savedSession = await this.userSessionRepository.save(session);

    try {
      const redisClient = new Redis({
        host: config.redis.host,
        port: +config.redis.port,
        username: config.redis.username,
        password: config.redis.password,
      });
      const key = `active_session:${user.id}:${savedSession.id}`;
      await redisClient.set(key, refreshToken, 'EX', refreshExpirySeconds);
      redisClient.disconnect();
    } catch (err) {
      // Redis failure should not block login; log in production
    }

    const access_token = this.jwtService.sign({ id: user.id, sub: user.id, email: user.email });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.OAUTH_LOGIN_SUCCESSFUL,
      access_token,
      refresh_token: refreshToken,
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
}
