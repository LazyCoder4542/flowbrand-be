import { Body, Controller, HttpCode, HttpStatus, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { skipAuth } from '@shared/helpers/skipAuth';
import AuthenticationService from './auth.service';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { SendOtpDocs, VerifyOtpDocs, ResendOtpDocs, LoginDocs, ChangePasswordDocs, RegisterDocs } from './docs/auth-swagger.doc';

@ApiTags('Authentication')
@Controller('auth')
export default class RegistrationController {
  constructor(private readonly authService: AuthenticationService) { }

  @skipAuth()
  @RegisterDocs()
  @Post('register')
  async register(@Body() body: CreateUserDTO) {
    return this.authService.createNewUser(body);
  }

  @skipAuth()
  @Post('login')
  @LoginDocs()
  async login(@Body() loginDto: LoginDto) {
    return this.authService.loginUser(loginDto);
  }

  @Post('change-password')
  @ChangePasswordDocs()
  async changePassword(@Body() body: ChangePasswordDto, @Req() request: Request) {
    const user = request['user'] as { id: string };
    return this.authService.changePassword(user.id, body.oldPassword, body.newPassword);
  }

  @skipAuth()
  @Post('send-otp')
  @SendOtpDocs()
  async sendOtp(@Body() body: SendOtpDto) {
    return this.authService.sendOtp(body.email);
  }

  @skipAuth()
  @Post('verify-otp')
  @VerifyOtpDocs()
  async verifyOtp(@Body() body: VerifyOtpDto) {
    return this.authService.verifyOtp(body.email, body.otp);
  }

  @skipAuth()
  @Post('resend-otp')
  @ResendOtpDocs()
  async resendOtp(@Body() body: SendOtpDto) {
    return this.authService.resendOtp(body.email);
  }
}
