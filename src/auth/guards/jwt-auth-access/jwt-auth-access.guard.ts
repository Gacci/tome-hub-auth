import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { TokenType } from '@/auth/models/session-token.model';
import { JwtPayload } from '@/common/interfaces/jwt-payload.interface';
import {
  JWT_ACCESS_TOKEN_NAME,
  JWT_REFRESH_TOKEN_NAME
} from '@/config/constants';
import { RedisService } from '@/redis/redis.service';

import { Request } from 'express';

@Injectable()
export class JwtAuthAccessGuard
  extends AuthGuard('jwt-access')
  implements CanActivate
{
  constructor(
    @Inject('REDIS_AUTH_ACCESS_REVOKED') private readonly redis: RedisService
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>();

    const accessAuthToken: string | null =
      request.cookies?.[JWT_ACCESS_TOKEN_NAME];
    const refreshAuthToken: string | null =
      request.cookies?.[JWT_REFRESH_TOKEN_NAME];

    if (!accessAuthToken && !refreshAuthToken) {
      throw new UnauthorizedException({
        error: 'SessionExpired',
        message: 'Session has expired. Please login.'
      });
    }

    if (!accessAuthToken) {
      throw new UnauthorizedException({
        error: 'AccessTokenExpired',
        message: 'Access token has expired.'
      });
    }

    // First, ensure the JWT is valid. If authentication failed, result will be false
    if (!(await super.canActivate(context))) {
      return false;
    }

    console.log('JwtAuthAccessGuard.canActivate', request.cookies);
    if (request.user.type !== TokenType.ACCESS) {
      throw new UnauthorizedException({
        error: 'TokenMismatch',
        message: `Unexpected token type: ${request.user.type}`
      });
    }

    if (await this.redis.getKey(accessAuthToken)) {
      throw new UnauthorizedException({
        error: 'AccessTokenRevoked',
        message: 'Access token has been revoked.'
      });
    }

    return true;
  }
}
