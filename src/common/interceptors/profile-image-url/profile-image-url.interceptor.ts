import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor
} from '@nestjs/common';

import { S3StorageService } from '@/common/services/s3-storage/s3-storage.service';

import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ProfileDto } from 'src/auth/dto/profile.dto';

@Injectable()
export class ProfileImageUrlInterceptor implements NestInterceptor {
  constructor(private readonly s3: S3StorageService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((user: ProfileDto) => ({
        ...user,
        ...(user?.profilePictureUrl
          ? {
              profilePictureUrl: this.s3.getProfileImageUrl(
                user.profilePictureUrl
              )
            }
          : {})
      }))
    );
  }
}
