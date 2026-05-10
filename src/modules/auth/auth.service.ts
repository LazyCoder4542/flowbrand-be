import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { UserSession } from './entities/user-session.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { RedisService } from '@modules/redis/services/redis.service';
import { randomInt } from 'crypto';
import { EmailService } from '@modules/email/email.service';
import { FRONTEND_RESET_PASSWORD } from '@shared/constants/app-constants';

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
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly emailService: EmailService
  ) {}

  async createNewUser(createUserDto: CreateUserDTO) {
    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

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

    user.password = await this.hashPassword(newPassword);
    await this.userRepository.save(user);

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.PASSWORD_UPDATED,
    };
  }

  async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (user) {
      const otp = this.generateOtp();
      const key = `$reset_otp:${email}`;
      try {
        await this.redisService.set(key, otp, 300);
        await this.emailService.sendForgotPasswordMail(
          email,
          user.full_name,
          `${FRONTEND_RESET_PASSWORD}?email=${email}`,
          otp
        );
      } catch (err) {
        this.logger.error(`Failed to issue password reset OTP for ${email}`, (err as Error).message);
      }
    }
    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.FORGOT_PASSWORD_OTP_SENT,
    };
  }

  async resetPassword(email: string, otp: string, newPassword: string) {
    const key = `$reset_otp:${email}`;
    const storedOtp = await this.redisService.get(key);
    const user = await this.userRepository.findOne({ where: { email } });

    if (otp !== storedOtp) {
      throw new CustomHttpException(SYS_MSG.INCORRECT_TOTP_CODE, HttpStatus.BAD_REQUEST);
    }

    if (!user) {
      await this.redisService.del(key);
      throw new CustomHttpException(SYS_MSG.INCORRECT_TOTP_CODE, HttpStatus.BAD_REQUEST);
    }

    user.password = await this.hashPassword(newPassword);
    await this.userRepository.save(user);

    await this.redisService.del(key);
    await this.redisService.delByPattern(`active_session:${user.id}:*`);
    await this.userSessionRepository.update(
      { user_id: user.id, is_revoked: false },
      { is_revoked: true, revoked_at: new Date() }
    );

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
  }

  private computeOtpExpiry(): Date {
    return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
  }
}
