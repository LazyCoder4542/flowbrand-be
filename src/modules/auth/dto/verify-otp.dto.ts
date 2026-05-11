import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyOtpDto {
  @ApiProperty({ description: 'The email address of the user', example: 'user@example.com' })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: 'The 6-digit OTP code', example: '123456' })
  @IsString()
  @Length(6, 6, { message: 'OTP must be exactly 6 characters long' })
  @IsNotEmpty()
  otp: string;
}
