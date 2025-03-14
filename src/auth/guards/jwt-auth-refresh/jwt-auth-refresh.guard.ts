import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { Request } from 'express';

import { JwtPayload } from '../../../common/interfaces/jwt-payload.interface';
import { RedisService } from '../../../redis/redis.service';
import { TokenType } from '../../entities/session-token.entity';

@Injectable()
export class JwtAuthRefreshGuard
  extends AuthGuard('jwt-refresh')
  implements CanActivate
{
  constructor(private readonly redis: RedisService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // First, ensure the JWT is valid. If authentication failed, result will be false
    if (!(await super.canActivate(context))) {
      return false;
    }

    const request = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>();

    if (request.user.type !== TokenType.REFRESH) {
      throw new UnauthorizedException(
        `Unexpected token type: ${request.user.type}`
      );
    }

    if (await this.redis.getKey(request.cookies.refresh_token as string)) {
      throw new UnauthorizedException('Revoked token.');
    }

    return true;
  }
}
