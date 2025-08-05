import { ConfigService } from '@nestjs/config';

import { RedisService } from '@/redis/redis.service';

import Redis from 'ioredis';

import { JwtAuthAccessGuard } from './jwt-auth-access.guard';

describe('JwtAuthAccessGuard', () => {
  it('should be defined', () => {
    expect(new RedisService(new Redis(), new ConfigService())).toBeDefined();
  });
});
