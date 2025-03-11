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
  verifyAccountOtp: string;

  @Exclude()
  verifyAccountOtpIssuedAt: string;

  @Exclude()
  loginOtp: string;

  @Exclude()
  loginOtpIssuedAt: string;

  @Exclude()
  resetPasswordOtp: string;

  @Exclude()
  resetPasswordOtpIssuedAt: string;

  @Exclude()
  deletedAt: Date;

  @Expose()
  createdAt: Date;

  constructor(user: Partial<User | null>) {
    Object.assign(this, user instanceof User ? user.toJSON() : user);
  }
}
