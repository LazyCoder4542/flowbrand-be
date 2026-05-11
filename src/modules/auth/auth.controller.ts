import { Body, Controller, HttpCode, HttpStatus, Post, Req, Get, UseGuards, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { skipAuth } from '@shared/helpers/skipAuth';
import AuthenticationService from './auth.service';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
<<<<<<< BE-003-reset-password-flow
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
=======
import { GoogleOAuthProfile, OAuthLoginResponse } from './dto/google-oauth.dto';
import authConfig from '@config/auth.config';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { SendOtpDocs, VerifyOtpDocs, ResendOtpDocs, LoginDocs, ChangePasswordDocs, RegisterDocs } from './docs/auth-swagger.doc';
>>>>>>> dev

@ApiTags('Authentication')
@Controller('auth')
export default class RegistrationController {
  constructor(private readonly authService: AuthenticationService) {}

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

  @skipAuth()
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Initiate Google OAuth login' })
  @ApiResponse({ status: HttpStatus.FOUND, description: 'Redirects to Google consent screen' })
  async googleAuth(): Promise<void> {
    // Passport handles the redirect to Google
  }

  @skipAuth()
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Google OAuth callback handler' })
  @ApiResponse({ status: HttpStatus.FOUND, description: 'Redirects to dashboard on success' })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: SYS_MSG.GOOGLE_OAUTH_FAILED })
  async googleAuthRedirect(@Req() req: Request & { user?: GoogleOAuthProfile }, @Res() res: Response): Promise<void> {
    const payload = req.user;

   if (!payload) {
      const frontend = (authConfig().frontendUrl || '').replace(/\/$/, '');
      const target = frontend ? `${frontend}/login?error=oauth_failed` : '/login?error=oauth_failed';
      res.redirect(HttpStatus.FOUND, target);
      return;
    }

    try {
      const result: OAuthLoginResponse = await this.authService.handleOAuthLogin(payload);
      res.cookie('access_token', result.access_token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
      });

      const frontend = authConfig().frontendUrl || '';
      const target = frontend ? `${frontend.replace(/\/$/, '')}/dashboard` : '/dashboard';
      res.redirect(HttpStatus.FOUND, target);
    } catch (err: unknown) {
      const frontend = authConfig().frontendUrl || '';
      const isCustom = err instanceof CustomHttpException;
      const safeMessage = isCustom ? (err as any).message : SYS_MSG.GOOGLE_OAUTH_FAILED;

      // Prefer redirecting back to the frontend login with a short error code.
      const errorParam = isCustom ? encodeURIComponent(String(safeMessage)) : 'oauth_failed';
      const errorTarget = frontend
        ? `${frontend.replace(/\/$/, '')}/login?error=${errorParam}`
        : `/login?error=${errorParam}`;

      // Do not leak internal error details for unknown errors; log and redirect.
      if (!isCustom) {
        // preserve original error logging via console (Nest will capture logs too)

        console.error('OAuth login error:', err);
      }

      res.status(HttpStatus.FOUND).redirect(errorTarget);
    }
  }

  @ApiBearerAuth()
  @Post('change-password')
  @ChangePasswordDocs()
  async changePassword(@Body() body: ChangePasswordDto, @Req() request: Request) {
    const user = request['user'] as { id: string };
    return this.authService.changePassword(user.id, body.oldPassword, body.newPassword);
  }

  @skipAuth()
<<<<<<< BE-003-reset-password-flow
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request a password reset OTP' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({ status: HttpStatus.OK, description: SYS_MSG.FORGOT_PASSWORD_OTP_SENT })
  async forgotPassword(@Body() body: ForgotPasswordDto) {
    return this.authService.forgotPassword(body.email);
  }

  @skipAuth()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using OTP' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({ status: HttpStatus.OK, description: SYS_MSG.PASSWORD_UPDATED })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: SYS_MSG.INCORRECT_TOTP_CODE })
  async resetPassword(@Body() body: ResetPasswordDto) {
    return this.authService.resetPassword(body.email, body.otp, body.newPassword);
=======
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
>>>>>>> dev
  }
}
