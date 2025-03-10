import { ApiProperty } from '@nestjs/swagger';

import {
  IsOptional,
  IsPhoneNumber,
  IsString,
  MinLength
} from 'class-validator';

export class UpdateAuthDto {
  @ApiProperty({
    description: "User's first name",
    example: 'John',
    nullable: true,
    required: false
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  firstName?: string | null;

  @ApiProperty({
    description: "User's last name",
    example: 'Doe',
    nullable: true,
    required: false
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  lastName?: string | null;

  @ApiProperty({
    description: "User's cell phone number in international format",
    example: '+15551234567',
    nullable: true,
    required: false
  })
  @IsOptional()
  @IsPhoneNumber()
  cellPhoneNumber?: string | null;

  @ApiProperty({
    description: "User's cell phone carrier",
    example: 'Verizon',
    nullable: true,
    required: false
  })
  @IsOptional()
  @IsString()
  cellPhoneCarrier?: string | null;

  @IsOptional()
  @IsString()
  profilePictureUrl?: string | null;
}
