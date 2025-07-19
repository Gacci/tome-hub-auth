import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { Request } from 'express';

import { JwtPayload } from '../../../common/interfaces/jwt-payload.interface';
import { JWT_ACCESS_TOKEN_NAME } from '../../../config/constants';
import { RedisService } from '../../../redis/redis.service';
import { TokenType } from '../../models/session-token.model';

@Injectable()
export class JwtAuthAccessGuard
  extends AuthGuard('jwt-access')
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

    if (request.user.type !== TokenType.ACCESS) {
      throw new UnauthorizedException(
        `Unexpected token type: ${request.user.type}`
      );
    }

    if (
      await this.redis.getKey(request.cookies[JWT_ACCESS_TOKEN_NAME] as string)
    ) {
      throw new UnauthorizedException('Revoked token.');
    }

    return true;
  }

  // Optionally override handleRequest to customize error handling
  handleRequest<JwtPayload>(err: any, jwt: JwtPayload, info: any) {
    console.log(
      '\nJwtAuthAccess\n',
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
