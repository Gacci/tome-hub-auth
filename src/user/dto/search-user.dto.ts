import { Transform } from 'class-transformer';
import {
  IsArray,
  IsEmail,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Min
} from 'class-validator';

export class SearchUsersDto {
  @IsOptional()
  @Transform(({ value }) => {
    console.log(value, typeof value);
    return value?.length && typeof value === 'string'
      ? value.split(',').map(Number)
      : value;
  })
  @IsArray()
  @IsInt({ each: true })
  userId?: number[];

  @IsOptional()
  @Transform(({ value }) => (value !== undefined ? Number(value) : undefined))
  @IsInt()
  collegeId?: number;

  @IsOptional()
  @Transform(({ value }) =>
    typeof value?.length && value === 'string'
      ? value.split(',').map(Number)
      : value
  )
  @IsArray()
  @IsString({ each: true })
  @IsEmail({}, { each: true })
  email?: string[];

  @IsOptional()
  @Transform(({ value }) => (value !== undefined ? Number(value) : undefined))
  @IsInt()
  @IsIn([10, 20, 50])
  pageSize: number = 10;

  @IsOptional()
  @Transform(({ value }) => (value !== undefined ? Number(value) : undefined))
  @IsInt()
  @Min(1)
  pageNumber: number = 1;

  // get userId() {
  //   return this['userId[]'];
  // }
}
