import { Expose } from 'class-transformer';

import { User } from '../../user/user.model';

export class ProfilePictureUrlDto {
  @Expose()
  profilePictureUrl?: string | null | undefined;

  constructor(user: Partial<User | null>) {
    this.profilePictureUrl = user?.profilePictureUrl;
  }
}
