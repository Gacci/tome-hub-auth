import { ApiProperty } from '@nestjs/swagger';

import { IsNotEmpty, IsString } from 'class-validator';

import { Match } from '../../common/decorators/match.decorator';
import { CredentialsDto } from './credentials.dto';

export class RegisterAuthDto extends CredentialsDto {
  @ApiProperty({
    example: 'NewPassword123!',
    description: 'Confirm password'
  })
  @IsString()
  @IsNotEmpty()
  @Match('password')
  confirmation: string;
}
