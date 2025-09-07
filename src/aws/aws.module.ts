import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AwsConfigService } from '@/aws/aws-config.service';
import { EnvironmentService } from '@/common/services/environment/environment.service';

@Module({
  imports: [ConfigModule.forRoot()],
  providers: [AwsConfigService, EnvironmentService]
})
export class AwsModule {}
