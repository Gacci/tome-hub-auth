import Redis from 'ioredis';

import { RedisService } from '@/redis/redis.service';
import { JwtAuthRefreshGuard } from '@/auth/guards/jwt-auth-refresh/jwt-auth-refresh.guard';

describe('JwtAuthRefreshGuard', () => {
  it('should be defined', () => {
    expect(
      new JwtAuthRefreshGuard(
        new RedisService(new Redis(), 'refresh')
      )
    ).toBeDefined();
  });
});
