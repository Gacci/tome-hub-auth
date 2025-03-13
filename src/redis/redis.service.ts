import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { RedisClientType, createClient } from 'redis';

@Injectable()
export class RedisService implements OnModuleInit {
  private client: RedisClientType;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    this.client = createClient({
      url: this.configService.get('REDIS_URL')
    });

    await this.client.connect();
  }

  async setKey(key: string, value: string, ttl?: number): Promise<void> {
    await this.client.set(key, value);
    if (ttl) {
      await this.client.expire(key, ttl);
    }
  }

  async getKey(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async deleteKey(key: string): Promise<void> {
    await this.client.del(key);
  }
}
