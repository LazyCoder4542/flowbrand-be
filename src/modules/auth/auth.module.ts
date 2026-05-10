import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import RegistrationController from './auth.controller';
import authConfig from '@config/auth.config';
import AuthenticationService from './auth.service';
import { GoogleStrategy } from '../strategies/google.strategy';
import { AuthMetadata } from './entities/auth-metadata.entity';
import { UserSession } from './entities/user-session.entity';
import { RedisModule } from '@modules/redis/redis.module';
import { LockoutService } from './lockout.service';
import { SessionService } from './session.service';
import type { StringValue } from 'ms';

const expiry = authConfig().jwtExpiry;
@Module({
  controllers: [RegistrationController],
  providers: [AuthenticationService, GoogleStrategy],
  imports: [
    PassportModule,
    JwtModule.register({
      global: true,
      secret: authConfig().jwtSecret,
      signOptions: {
        expiresIn: `${expiry}` as unknown as StringValue,
      },
    }),
    RedisModule,
  ],
  exports: [],
})
export class AuthModule {}
