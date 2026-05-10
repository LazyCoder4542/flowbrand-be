import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, IsStrongPassword, Length, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({ description: 'Email address of the account', example: 'jane@example.com' })
  @IsNotEmpty()
  @IsEmail()
  readonly email: string;

  @ApiProperty({ description: 'OTP sent to the email', example: '482910' })
  @IsNotEmpty()
  @IsString()
  @Length(6, 6)
  readonly otp: string;

  @ApiProperty({ description: 'New password', example: 'NewP@ssword123' })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    }
  )
  readonly newPassword: string;
}
