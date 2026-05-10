import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { skipAuth } from '@shared/helpers/skipAuth';
import AuthenticationService from './auth.service';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { SendOtpDocs, VerifyOtpDocs, ResendOtpDocs, LoginDocs, ChangePasswordDocs } from './docs/auth-swagger.doc';

@ApiTags('Authentication')
@Controller('auth')
export default class RegistrationController {
  constructor(private readonly authService: AuthenticationService) { }

  @skipAuth()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: CreateUserDTO })
  @ApiResponse({ status: HttpStatus.CREATED, description: SYS_MSG.USER_CREATED_SUCCESSFULLY })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: SYS_MSG.USER_ACCOUNT_EXIST })
  async register(@Body() body: CreateUserDTO, @Res({ passthrough: true }) response: Response) {
    return this.authService.createNewUser(body, response);
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
