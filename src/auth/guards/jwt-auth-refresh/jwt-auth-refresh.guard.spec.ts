import { ConfigService } from '@nestjs/config';

import Redis from 'ioredis';

import { RedisService } from '../../../redis/redis.service';
import { JwtAuthRefreshGuard } from './jwt-auth-refresh.guard';

describe('JwtAuthRefreshGuard', () => {
  it('should be defined', () => {
    expect(
      new JwtAuthRefreshGuard(
        new RedisService(new Redis(), new ConfigService())
      )
    ).toBeDefined();
  });
});
