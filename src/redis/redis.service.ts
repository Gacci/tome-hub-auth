import { Inject, Injectable } from '@nestjs/common';

import Redis from 'ioredis';

@Injectable()
export class RedisService {
  constructor(
    @Inject('REDIS_CLIENT') private readonly client: Redis,
    @Inject('REDIS_PREFIX') private readonly prefix: string
  ) {}

  async setKey(key: string, value: string, ttl?: number): Promise<void> {
    await this.client.set(`${this.prefix}:${key}`, value);
    if (ttl) {
      await this.client.expire(`${this.prefix}:${key}`, ttl);
    }
  }

  async getKey(key: string): Promise<string | null> {
    return this.client.get(`${this.prefix}:${key}`);
  }

  async deleteKey(key: string): Promise<void> {
    await this.client.del(`${this.prefix}:${key}`);
  }
}
