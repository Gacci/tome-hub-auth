import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { Request } from 'express';

import { AuthService } from '../../auth.service';
import { IS_PUBLIC_KEY } from '../../decorators/public.decorator';

@Injectable()
export class BlacklistGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private authService: AuthService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.get<boolean>(
      IS_PUBLIC_KEY,
      context.getHandler()
    );

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    if (!request.headers.authorization) {
      throw new UnauthorizedException('Token missing.');
    }

    const authorization = request.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) {
      throw new BadRequestException('Bad Request');
    }

    const jwtRawToken = authorization?.replace(/^Bearer\s/, '');
    if (!jwtRawToken) {
      throw new UnauthorizedException('Token missing.');
    }

    if (await this.authService.isTokenBlacklisted(jwtRawToken)) {
      throw new UnauthorizedException('Token revoked.');
    }

    return true;
  }
}
