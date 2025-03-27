import { ApiProperty } from '@nestjs/swagger';

import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Matches
} from 'class-validator';

export class VerifyAccountDto {
  @ApiProperty({
    description: "User's registered email address",
    example: 'user@example.com'
  })
  @IsEmail()
  @IsNotEmpty()
  @Matches(/\.edu$/, {
    message: 'Email must be an academic email (.edu)'
  })
  email: string;

  @ApiProperty({
    description: 'One-Time Password (OTP)',
    example: '123456',
    required: false
  })
  @IsOptional()
  @IsString()
  @Length(6)
  @Matches(/^\d{6}$/)
  verifyAccountOtp?: string;
}
