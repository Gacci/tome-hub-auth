import { Exclude, Expose } from 'class-transformer';

import { User } from '../../user/user.model';

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

  @Expose()
  profilePictureUrl: string;

  @Expose()
  is2faEnabled: boolean;

  @Expose()
  cellPhoneNumber: string;

  @Expose()
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
  resetPasswordToken: string;

  @Exclude()
  resetPasswordTokenIssuedAt: string;

  @Exclude()
  deletedAt: Date;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;

  constructor(user: Partial<User | null>) {
    Object.assign(this, user instanceof User ? user.toJSON() : user);
  }
}
