import { ApiProperty } from '@nestjs/swagger';

import { IsString, Length, Matches } from 'class-validator';

export class OtpDto {
  @ApiProperty({
    description: 'One-Time Password (OTP)',
    example: '123456',
    required: true
  })
  @IsString()
  @Length(6)
  @Matches(/^[A-Za-z0-9]{6}$/)
  otp: string;
}
