import { Expose } from 'class-transformer';

import { User } from '../../user/user.entity';

export class ProfilePictureUrlDto {
  @Expose()
  profilePictureUrl?: string | null | undefined;

  constructor(user: Partial<User | null>) {
    this.profilePictureUrl = user?.profilePictureUrl;
  }
}
