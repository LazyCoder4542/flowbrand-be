import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsStrongPassword,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDTO {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'The full name of the user',
    example: 'John Doe',
  })
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  full_name: string;

  @ApiProperty({
    description: 'The country of the user',
    example: 'Nigeria',
    required: false,
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  country?: string;

  @ApiProperty({
    description:
      'The password for the user account. Must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    example: 'P@ssw0rd!',
  })
  @MinLength(8)
  @IsNotEmpty()
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    }
  )
  password: string;

  @ApiProperty({
    description: 'The user must accept the Terms and Conditions of the application to continue with signup',
    example: true,
    required: true,
  })
  @IsBoolean()
  @IsNotEmpty()
  terms_accepted: boolean;
}
