import { applyDecorators, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SendOtpDto } from '../dto/send-otp.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { LoginDto } from '../dto/login.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { CreateUserDTO } from '../dto/create-user.dto';

export function SendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Send OTP to user email' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'OTP sent successfully' })
  );
}

export function VerifyOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Verify OTP' }),
    ApiBody({ type: VerifyOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'Email verified successfully' }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid OTP or expired' }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Too many attempts' })
  );
}

export function ResendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Resend OTP to user email' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'OTP sent successfully' }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Rate limit exceeded' })
  );
}

export function LoginDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Login with email and password' }),
    ApiBody({ type: LoginDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns access_token (JWT with sid), refresh_token, expires_at, and user object.',
    }),
    ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid email or password.' }),
    ApiResponse({
      status: HttpStatus.FORBIDDEN,
      description: 'Account locked. Returns remaining lockout seconds in message.',
    })
  );
}

export function RegisterDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.CREATED),
    ApiOperation({ summary: 'Register a new user' }),
    ApiBody({ type: CreateUserDTO }),
    ApiResponse({ status: HttpStatus.CREATED, description: 'User Created Successfully' }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Account with the specified email exists' })
  );
}

export function ChangePasswordDocs() {
  return applyDecorators(
    ApiBearerAuth(),
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Change authenticated user password' }),
    ApiBody({ type: ChangePasswordDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'Password updated successfully.' }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Old password is incorrect.' }),
    ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Missing or invalid bearer token.' })
  );
}
