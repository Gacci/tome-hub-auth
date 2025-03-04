import {
  IsOptional,
  IsPhoneNumber,
  IsString,
  MinLength
} from 'class-validator';

import { ApiProperty } from '@nestjs/swagger';

export class UpdateAuthDto {
  @ApiProperty({
    example: 'John',
    description: "User's first name",
    required: false,
    nullable: true
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  firstName?: string | null;

  @ApiProperty({
    example: 'Doe',
    description: "User's last name",
    required: false,
    nullable: true
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  lastName?: string | null;

  @ApiProperty({
    example: '+15551234567',
    description: "User's cell phone number in international format",
    required: false,
    nullable: true
  })
  @IsOptional()
  @IsPhoneNumber()
  cellPhoneNumber?: string | null;

  @ApiProperty({
    example: 'Verizon',
    description: "User's cell phone carrier",
    required: false,
    nullable: true
  })
  @IsOptional()
  @IsString()
  cellPhoneCarrier?: string | null;
}
