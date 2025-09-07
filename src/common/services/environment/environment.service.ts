import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { RuntimeEnvironment } from '@/common/enums/runtime-environment.enum';

@Injectable()
export class EnvironmentService {
  private readonly env: RuntimeEnvironment;

  constructor(private readonly configService: ConfigService) {
    this.env = this.configService.get<string>(
      'APP_ENV',
      'development'
    ) as RuntimeEnvironment;
  }

  isDevelopment(): boolean {
    return this.env === RuntimeEnvironment.DEV;
  }

  isLocal(): boolean {
    return this.env === RuntimeEnvironment.LOCAL;
  }

  isStaging(): boolean {
    return this.env === RuntimeEnvironment.STAGING;
  }

  isProduction(): boolean {
    return this.env === RuntimeEnvironment.PROD;
  }

  getCurrent(): RuntimeEnvironment {
    return this.env;
  }
}
