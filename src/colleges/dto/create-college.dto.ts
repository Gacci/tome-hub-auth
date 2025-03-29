import { IsNotEmpty, IsString } from 'class-validator';

export class CreateCollegeDto {
  @IsNotEmpty()
  @IsString()
  locationName: string;

  @IsNotEmpty()
  @IsString()
  emailDomain: string;
}
