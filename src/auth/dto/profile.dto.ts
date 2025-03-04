import { Exclude, Expose } from 'class-transformer';
import { User } from '../../user/user.entity';

export class ProfileDto {
  @Expose()
  userId: number;

  @Expose()
  email: string;

  @Exclude()
  password: string;

  @Expose()
  firstName: string;

  @Expose()
  lastName: string;

  @Exclude()
  is2faEnrolled: boolean;

  @Exclude()
  cellPhoneNumber: string;

  @Exclude()
  cellPhoneCarrier: string;

  @Exclude()
  loginOtp: string;

  @Exclude()
  loginOtpExpiresAt: string;

  @Exclude()
  resetPasswordOtp: string;

  @Exclude()
  resetPasswordOtpExpiresAt: string;

  @Exclude()
  deletedAt: Date;

  @Expose()
  createdAt: Date;

  constructor(partial: Partial<User | null>) {
    Object.assign(this, partial);
  }
}
