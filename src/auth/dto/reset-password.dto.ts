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
import { Match } from '../../common/decorators/match.decorator';

export class ResetPasswordDto {
  @ApiProperty({
    example: 'user@example.com',
    description: "User's registered email address"
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: 'NewPassword123!',
    description:
      'New password (must contain uppercase, lowercase, numbers, or special characters)',
    minLength: 4,
    maxLength: 20
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
    example: 'NewPassword123!',
    description: 'Confirmation of the new password (must match newPassword)',
  })
  @IsString()
  @IsNotEmpty()
  @Match('newPassword')
  confirmation: string;

  @ApiProperty({
    example: '123456',
    description: "One-Time Password (OTP) sent to the user's email",
    minLength: 6,
    maxLength: 6
  })
  @IsString()
  @IsNotEmpty()
  @Length(6)
  resetPasswordOtp: string;
}
