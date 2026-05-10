import { applyDecorators, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { LoginDto } from '../dto/login.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';

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
