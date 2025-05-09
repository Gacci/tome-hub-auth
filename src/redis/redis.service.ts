import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import Redis from 'ioredis';

@Injectable()
export class RedisService {
  constructor(
    @Inject('REDIS') private readonly redis: Redis,
    private readonly configService: ConfigService
  ) {}

  async setKey(key: string, value: string, ttl?: number): Promise<void> {
    await this.redis.set(key, value);
    if (ttl) {
      await this.redis.expire(key, ttl);
    }
  }

  async getKey(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async deleteKey(key: string): Promise<void> {
    await this.redis.del(key);
  }
}
