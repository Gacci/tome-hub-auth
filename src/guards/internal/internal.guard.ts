import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { Request } from 'express';

@Injectable()
export class InternalGuard implements CanActivate {
  constructor(private readonly configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const headerKey = request.headers['x-internal-api-key'];

    if (!headerKey) {
      throw new UnauthorizedException('Missing API key');
    }

    if (typeof headerKey !== 'string') {
      throw new UnauthorizedException('Invalid API key.');
    }

    const keys = this.configService
      .get<string>('INTERNAL_API_KEYS', '')
      .split(',')
      .map(k => k.trim());

    console.log('\nheaderKey: ', headerKey, '\nkeys: ', keys);
    if (!keys.includes(headerKey)) {
      throw new UnauthorizedException('Unauthorized internal access.');
    }

    return true;
  }
}
