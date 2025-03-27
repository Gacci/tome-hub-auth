import { ApiProperty } from '@nestjs/swagger';

import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator';

import { Match } from '../../common/validators/match.decorator';

export class ResetPasswordDto {
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
    description:
      'New password (must contain uppercase, lowercase, numbers, or special characters)',
    example: 'NewPassword123!',
    maxLength: 20,
    minLength: 4
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password too weak'
  })
  newPassword: string;

  @ApiProperty({
    description: 'Confirmation of the new password (must match newPassword)',
    example: 'NewPassword123!'
  })
  @IsString()
  @IsNotEmpty()
  @Match('newPassword')
  confirmation: string;

  @ApiProperty({
    description: "One-Time Password (OTP) sent to the user's email",
    example: '123456',
    maxLength: 6,
    minLength: 6
  })
  @IsString()
  @IsNotEmpty()
  @Length(6)
  resetPasswordOtp: string;
}
