import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AwsConfigService } from '@/aws/aws-config.service';

@Module({
  imports: [ConfigModule.forRoot()],
  providers: [AwsConfigService]
})
export class AwsModule {}
