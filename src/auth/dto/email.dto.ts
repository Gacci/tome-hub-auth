import { ApiProperty } from '@nestjs/swagger';

import { IsEmail, IsNotEmpty, Matches } from 'class-validator';

export class EmailDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com'
  })
  @IsEmail()
  @IsNotEmpty()
  @Matches(/\.edu$/, {
    message: 'Email must be an academic email (.edu)'
  })
  email: string;
}
