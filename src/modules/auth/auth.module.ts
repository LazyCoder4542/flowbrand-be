import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import authConfig from '@config/auth.config';
import { User } from '@modules/user/entities/user.entity';
import RegistrationController from './auth.controller';
import AuthenticationService from './auth.service';
import { AuthMetadata } from './entities/auth-metadata.entity';
import { UserSession } from './entities/user-session.entity';
import type { StringValue } from 'ms';
import { EmailModule } from '@modules/email/email.module';
import { EmailService } from '@modules/email/email.service';

const expiry = authConfig().jwtExpiry;
@Module({
  controllers: [RegistrationController],
  providers: [AuthenticationService],
  imports: [
    TypeOrmModule.forFeature([User, AuthMetadata, UserSession]),
    PassportModule,
    JwtModule.register({
      global: true,
      secret: authConfig().jwtSecret,
      signOptions: {
        expiresIn: `${expiry}` as unknown as StringValue,
      },
    }),
    EmailModule,
  ],
  exports: [TypeOrmModule],
})
export class AuthModule {}
