import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { S3Bucket } from '@/aws/aws-config.service';
import { EnvironmentService } from '@/common/services/environment/environment.service';

@Injectable()
export class S3StorageService {
  constructor(
    private readonly configService: ConfigService,
    private readonly env: EnvironmentService
  ) {}

  getProfileImageUrl(s3StorageKey: string) {
    return this.getFileUrl(s3StorageKey, S3Bucket.PROFILES);
  }

  getFileUrl(s3StorageKey: string, s3BucketName: string) {
    if (s3StorageKey?.startsWith('http')) {
      return s3StorageKey;
    }

    if (this.env.isDevelopment()) {
      return `http://localhost/media/${s3BucketName}/${s3StorageKey}`;
    }

    if (this.env.isLocal()) {
      return `http://localhost:4566/media/${s3BucketName}/${s3StorageKey}`;
    }

    if (this.env.isProduction()) {
      return `https://${s3BucketName}.s3.${this.configService.get<string>('AWS_S3_REGION')}.amazonaws.com/${s3StorageKey}`;
    }

    if (this.env.isStaging()) {
      return `http://sydebook.com/media/${s3BucketName}/${s3StorageKey}`;
    }

    return '';
  }
}
