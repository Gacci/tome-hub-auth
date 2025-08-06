import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import Redis from 'ioredis';
import { RedisService } from '@/redis/redis.service';

@Module({
  exports: ['REDIS_AUTH_ACCESS_REVOKED', 'REDIS_AUTH_REFRESH_REVOKED'],
  providers: [
    {
      inject: [ConfigService],
      provide: 'REDIS_CLIENT',
      useFactory: (configService: ConfigService) => {
        return new Redis({
          db: configService.get<number>('REDIS_DB', 0),
          host: configService.get<string>('REDIS_HOST', 'localhost'),
          port: configService.get<number>('REDIS_PORT', 6379)
        });
      }
    },
    {
      provide: 'REDIS_AUTH_REFRESH_REVOKED', // Pre-configured for auth
      inject: ['REDIS_CLIENT'],
      useFactory: (redis: Redis) => new RedisService(redis, 'revoked:refresh'),
    },
    {
      provide: 'REDIS_AUTH_ACCESS_REVOKED', // Pre-configured for cache
      inject: ['REDIS_CLIENT'],
      useFactory: (redis: Redis) => new RedisService(redis, 'revoked:access'),
    },
  ]
})
export class RedisModule {}
