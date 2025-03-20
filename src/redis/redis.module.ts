import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import Redis from 'ioredis';

@Module({
  exports: ['REDIS'],
  providers: [
    {
      inject: [ConfigService],
      provide: 'REDIS',
      useFactory: (configService: ConfigService) => {
        return new Redis({
          db: configService.get<number>('REDIS_DB', 0),
          host: configService.get<string>('REDIS_HOST', 'localhost'),
          port: configService.get<number>('REDIS_PORT', 6379)
        });
      }
    }
  ]
})
export class RedisModule {}
