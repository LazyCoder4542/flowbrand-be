import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { skipAuth } from '@shared/helpers/skipAuth';
import AuthenticationService from './auth.service';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';

@ApiTags('Authentication')
@Controller('auth')
export default class RegistrationController {
  constructor(private readonly authService: AuthenticationService) {}

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
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log a user in' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: SYS_MSG.LOGIN_SUCCESSFUL })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: SYS_MSG.INVALID_CREDENTIALS })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.loginUser(loginDto);
  }

  @ApiBearerAuth()
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Change a user password' })
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({ status: HttpStatus.OK, description: SYS_MSG.PASSWORD_UPDATED })
  async changePassword(@Body() body: ChangePasswordDto, @Req() request: Request) {
    const user = request['user'] as { id: string };
    return this.authService.changePassword(user.id, body.oldPassword, body.newPassword);
  }
}
