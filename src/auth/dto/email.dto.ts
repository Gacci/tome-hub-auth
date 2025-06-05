import { ApiProperty } from '@nestjs/swagger';

import { IsEmail, IsNotEmpty, Matches } from 'class-validator';

export class EmailDto {
  @ApiProperty({
    description: 'User email address',
    example: 'users@example.com'
  })
  @IsNotEmpty()
  @IsEmail()
  @Matches(/\.edu$/, {
    message: 'Email must be an academic email (.edu)'
  })
  email: string;
}
