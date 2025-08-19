import { Expose, plainToInstance } from 'class-transformer';

import { Membership } from '../../common/enums/membership.enum';
import { User } from '../../user/user.model';

export class ProfileDto {
  @Expose()
  userId: number;

  @Expose()
  collegeId: number;

  @Expose()
  email: string;

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

  @Expose()
  membership: Membership;

  @Expose()
  membershipExpiresAt: Date;

  @Expose()
  isAccountVerified: boolean;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;

  constructor(user: Partial<User | null>) {
    Object.assign(this, user);
  }

  static from(user: Partial<User | null>) {
    return plainToInstance(ProfileDto, user, {
      excludeExtraneousValues: true
    });
  }
}
