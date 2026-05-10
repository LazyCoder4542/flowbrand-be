import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import authConfig from '@config/auth.config';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UserSession } from './entities/user-session.entity';
import { GoogleOAuthProfile, OAuthLoginResponse } from './dto/google-oauth.dto';
import { v4 as uuidv4 } from 'uuid';
import { RedisService } from '@modules/redis/services/redis.service';
import authConfig from '@config/auth.config';
import { LockoutService } from './lockout.service';
import { SessionService } from './session.service';

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;

@Injectable()
export default class AuthenticationService {
  /**
   * TODO: Migration Plan - Email Case-Insensitive Uniqueness
   *
   * Currently, email normalization (.trim().toLowerCase()) is performed at the application level
   * in createNewUser(), loginUser(), and handleOAuthLogin(). This is a workaround.
   *
   * Recommended next step: Migrate the email column to PostgreSQL citext type to enforce
   * case-insensitive uniqueness at the database level. This will:
   * - Eliminate the need for application-level normalization
   * - Prevent race conditions during user lookup/creation
   * - Improve query performance for email-based searches
   *
   * Migration steps:
   * 1. Create a migration: ALTER TABLE "user" ALTER COLUMN "email" TYPE citext;
   * 2. Add unique constraint on citext column if not already present
   * 3. Remove application-level normalization (optional; keeping it adds defense-in-depth)
   * 4. Test thoroughly with both uppercase and lowercase email variants
   */
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserSession)
    private readonly userSessionRepository: Repository<UserSession>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly lockoutService: LockoutService,
    private readonly sessionService: SessionService
  ) {}

  async createNewUser(createUserDto: CreateUserDTO) {
    // Normalize email: trim whitespace and convert to lowercase
    // NOTE: This is a workaround until the email column is migrated to PostgreSQL citext
    // for case-insensitive uniqueness enforcement at the database level.
    const email = createUserDto.email.trim().toLowerCase();

    const existing = await this.userRepository.findOne({ where: { email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = this.userRepository.create({
      email,
      full_name: createUserDto.full_name,
      country: createUserDto.country ?? null,
      password: hashedPassword,
      auth_provider: 'email',
      otp_code: this.generateOtp(),
      expires_at: new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000),
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
    // Normalize email: trim whitespace and convert to lowercase
    // Matches normalization performed during user creation and OAuth login
    const email = loginDto.email.trim().toLowerCase();

    const user = await this.userRepository.findOne({ where: { email } });
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

  private generateOtp(): string {
    return Math.floor(Math.random() * 10 ** OTP_LENGTH)
      .toString()
      .padStart(OTP_LENGTH, '0');
  }

  private computeOtpExpiry(): Date {
    return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
  }

  /**
   * Hash a refresh token using HMAC-SHA256 for secure persistence.
   * @param token - The plaintext refresh token
   * @returns HMAC-SHA256 hash as hex string
   */
  private hashRefreshToken(token: string): string {
    const config = authConfig();
    const secret = config.jwtRefreshSecret;
    if (!secret) {
      throw new Error('jwtRefreshSecret is not configured');
    }
    return crypto.createHmac('sha256', secret).update(token).digest('hex');
  }

  /**
   * Verify a refresh token against its stored hash using constant-time comparison.
   * @param token - The plaintext refresh token from the client
   * @param hash - The stored hash from DB/Redis
   * @returns true if token matches hash, false otherwise
   *
   * Usage in refresh/revoke endpoints:
   *   const session = await userSessionRepository.findOne({ where: { id: sessionId } });
   *   const isValid = this.verifyRefreshToken(incomingRefreshToken, session.refresh_token);
   *   if (!isValid) throw new UnauthorizedException('Invalid refresh token');
   */
  private verifyRefreshToken(token: string, hash: string): boolean {
    const computed = this.hashRefreshToken(token);
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash));
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
    const refreshTokenHash = this.hashRefreshToken(refreshToken);
    const refreshExpirySeconds = Number(config.jwtRefreshExpiry) || 60 * 60 * 24 * 30;
    const session = this.userSessionRepository.create({
      user_id: user.id,
      refresh_token: refreshTokenHash,
      expires_at: new Date(Date.now() + refreshExpirySeconds * 1000),
      is_revoked: false,
    });

    const savedSession = await this.userSessionRepository.save(session);

    // Store refresh token hash in Redis using shared RedisService
    // Redis failure should not block login; swallow Redis errors so login proceeds
    const key = `active_session:${user.id}:${savedSession.id}`;
    try {
      await this.redisService.set(key, refreshTokenHash, refreshExpirySeconds);
    } catch (e) {
      // Log and continue — do not block the OAuth login flow for Redis failures

      console.error('Redis set failed during OAuth login:', e);
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
