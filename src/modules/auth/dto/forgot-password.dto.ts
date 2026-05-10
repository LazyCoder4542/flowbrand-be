import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({ description: 'Email address of the account', example: 'jane@example.com' })
  @IsNotEmpty()
  @IsEmail()
  readonly email: string;
}
