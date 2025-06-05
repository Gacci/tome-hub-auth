import { Expose, plainToInstance } from 'class-transformer';

import { User } from '../../user/user.model';

export class ProfilePictureUrlDto {
  @Expose()
  profilePictureUrl?: string | null | undefined;

  constructor(user: Partial<User | null>) {
    this.profilePictureUrl = user?.profilePictureUrl;
  }

  static from(user: Partial<User | null>) {
    return plainToInstance(ProfilePictureUrlDto, user, {
      excludeExtraneousValues: true
    });
  }
}
