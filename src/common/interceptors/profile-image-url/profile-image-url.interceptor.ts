import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ProfileDto } from 'src/auth/dto/profile.dto';

import { S3Bucket } from '../../../aws/aws-config.service';

@Injectable()
export class ProfileImageUrlInterceptor implements NestInterceptor {
  constructor(private readonly configService: ConfigService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((user: ProfileDto) => ({
        ...user,
        ...(user?.profilePictureUrl
          ? { profilePictureUrl: this.getImageUrl(user.profilePictureUrl) }
          : {})
      }))
    );
  }

  private getImageUrl(profilePictureUrl: string) {
    if (profilePictureUrl?.startsWith('http')) {
      return profilePictureUrl;
    }

    return 'prod' === this.configService.get<string>('NODE_ENV', 'dev')
      ? `https://${S3Bucket.PROFILES}.s3.${this.configService.get('AWS_S3_REGION')}.amazonaws.com/${profilePictureUrl}`
      : `http://localhost:4566/${S3Bucket.PROFILES}/${profilePictureUrl}`;
  }
}
