import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import {
  CreateBucketCommand,
  HeadBucketCommand,
  PutObjectCommand,
  S3Client
} from '@aws-sdk/client-s3';

import crypto from 'crypto';
import multer from 'multer';
import { extname } from 'path';

export enum S3Bucket {
  PROFILES = 'profiles'
}

@Injectable()
export class AwsConfigService {
  private readonly logger = new Logger(AwsConfigService.name);
  private readonly s3Client: S3Client;

  constructor(private readonly configService: ConfigService) {
    this.s3Client = new S3Client({
      credentials: {
        accessKeyId: this.configService.getOrThrow('AWS_ACCESS_KEY_ID'),
        secretAccessKey: this.configService.getOrThrow('AWS_SECRET_ACCESS_KEY')
      },
      endpoint: this.configService.getOrThrow('AWS_GATEWAY'),
      forcePathStyle: true,
      region: this.configService.getOrThrow('AWS_S3_REGION')
    });
  }

  getMulterS3Storage() {
    return multer({ storage: multer.memoryStorage() });
  }

  isAllowedBucket(s3BucketKey: S3Bucket) {
    return Object.values(S3Bucket).includes(s3BucketKey);
  }

  async exists(bucketName: S3Bucket): Promise<boolean> {
    try {
      await this.s3Client.send(new HeadBucketCommand({ Bucket: bucketName }));
      return true;
    } catch (error) {
      this.logger.error(error);
      return false;
    }
  }

  async upload(bucketName: S3Bucket, file: Express.Multer.File) {
    if (!this.isAllowedBucket(bucketName)) {
      throw new BadRequestException('Specified S3 bucket is not allowed.');
    }

    if (!(await this.exists(bucketName))) {
      await this.s3Client.send(
        new CreateBucketCommand({
          Bucket: bucketName
        })
      );
    }

    const unique = `${(Date.now().toString() + crypto.randomBytes(16).toString('hex')).slice(0, 32).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5')}${extname(file.originalname)}`;
    await this.s3Client.send(
      new PutObjectCommand({
        Body: file.buffer,
        Bucket: bucketName,
        Key: unique
      })
    );

    return {
      filename: unique,
      url:
        'prod' === this.configService.get<string>('NODE_ENV', 'dev')
          ? `https://${bucketName}.s3.${this.configService.get('AWS_S3_REGION')}.amazonaws.com/${unique}`
          : `http://localhost:4566/${bucketName}/${unique}`
    };
  }
}
