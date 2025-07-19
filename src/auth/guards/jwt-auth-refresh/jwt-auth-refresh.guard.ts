import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { Request } from 'express';

import { JwtPayload } from '../../../common/interfaces/jwt-payload.interface';
import { JWT_REFRESH_TOKEN_NAME } from '../../../config/constants';
import { RedisService } from '../../../redis/redis.service';
import { TokenType } from '../../models/session-token.model';

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
        `Refresh token error: unexpected token type: ${request.user.type}`
      );
    }

    if (
      await this.redis.getKey(request.cookies[JWT_REFRESH_TOKEN_NAME] as string)
    ) {
      throw new UnauthorizedException('Refresh token error: revoked token.');
    }

    return true;
  }

  handleRequest<JwtPayload>(err: any, jwt: JwtPayload, info: any): JwtPayload {
    console.log(
      '\nJwtAuthRefresh\n',
      '\nERROR: \n', err,
      '\nJWT: \n', jwt,
      '\nINFO\n', info
    );

    if (err) {
      throw err;
    }

    if (!jwt) {
      throw new UnauthorizedException('NoAuthToken: Auth token missing.');
    }

    return jwt;
  }
}
