import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { getRepositoryToken, TypeOrmModule } from '@nestjs/typeorm';
import RegistrationController from './auth.controller';
import authConfig from '@config/auth.config';
import AuthenticationService from './auth.service';
import { AuthMetadata } from './entities/auth-metadata.entity';
import { UserSession } from './entities/user-session.entity';
import { RedisModule } from '@modules/redis/redis.module';
import { EmailModule } from '@modules/email/email.module';
import { GoogleStrategy } from '../strategies/google.strategy';
import { LockoutService } from './lockout.service';
import { SessionService } from './session.service';
import type { StringValue } from 'ms';
import { User } from '@modules/user/entities/user.entity';

const expiry = authConfig().jwtExpiry;
@Module({
  controllers: [RegistrationController],
  providers: [
    AuthenticationService,
    GoogleStrategy,
    {
      provide: LockoutService,
      useFactory: authMetadataRepository => new LockoutService(authMetadataRepository),
      inject: [getRepositoryToken(AuthMetadata)],
    },
    {
      provide: SessionService,
      useFactory: userSessionRepository => new SessionService(userSessionRepository),
      inject: [getRepositoryToken(UserSession)],
    },
  ],
  imports: [
    PassportModule,
    TypeOrmModule.forFeature([User, UserSession, AuthMetadata]),
    RedisModule,
    EmailModule,
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
