import { JwtAuthRefreshGuard } from '@/auth/guards/jwt-auth-refresh/jwt-auth-refresh.guard';
import { RedisService } from '@/redis/redis.service';

import Redis from 'ioredis';

describe('JwtAuthRefreshGuard', () => {
  it('should be defined', () => {
    expect(
      new JwtAuthRefreshGuard(new RedisService(new Redis(), 'refresh'))
    ).toBeDefined();
  });
});
