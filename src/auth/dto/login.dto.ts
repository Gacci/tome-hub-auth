import { ApiProperty } from '@nestjs/swagger';

import {
  IsOptional,
  IsString,
  Length,
  Matches
} from 'class-validator';

import { CredentialsDto } from './credentials.dto';


export class LoginAuthDto extends CredentialsDto {
  @ApiProperty({ example: '123456', description: 'One-Time Password (OTP)', required: false })
  @IsOptional()
  @IsString()
  @Length(6)
  @Matches(/^\d{6}$/)
  loginOtp?: string;
}
