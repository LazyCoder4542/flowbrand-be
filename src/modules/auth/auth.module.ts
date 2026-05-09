import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import authConfig from '@config/auth.config';
import { User } from '@modules/user/entities/user.entity';
import RegistrationController from './auth.controller';
import AuthenticationService from './auth.service';
import { GoogleStrategy } from '../strategies/google.strategy';
import { AuthMetadata } from './entities/auth-metadata.entity';
import { UserSession } from './entities/user-session.entity';

@Module({
  controllers: [RegistrationController],
  providers: [AuthenticationService, GoogleStrategy],
  imports: [
    TypeOrmModule.forFeature([User, AuthMetadata, UserSession]),
    PassportModule,
    JwtModule.register({
      global: true,
      secret: authConfig().jwtSecret,
      signOptions: { expiresIn: Number(authConfig().jwtExpiry) || 3600 },
    }),
  ],
  exports: [TypeOrmModule],
})
export class AuthModule {}
