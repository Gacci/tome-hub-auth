import { ApiProperty } from '@nestjs/swagger';

import { IsNotEmpty, IsString } from 'class-validator';

import { Match } from '../../common/validators/match.decorator';
import { CredentialsDto } from './credentials.dto';

export class RegisterAuthDto extends CredentialsDto {
  @ApiProperty({
    description: 'Confirm password',
    example: 'NewPassword123!'
  })
  @IsString()
  @IsNotEmpty()
  @Match('password')
  confirmation: string;
}
