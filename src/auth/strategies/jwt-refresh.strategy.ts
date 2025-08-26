import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

import { Request } from 'express';
import { Strategy } from 'passport-jwt';

import { JwtPayload } from '@/common/interfaces/jwt-payload.interface';
import { JWT_REFRESH_TOKEN_NAME } from '@/config/constants';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh'
) {
  constructor(private readonly configService: ConfigService) {
    super({
      ignoreExpiration: false,
      jwtFromRequest: (req: Request): string | null =>
        req.cookies?.[JWT_REFRESH_TOKEN_NAME]
          ? (req.cookies[JWT_REFRESH_TOKEN_NAME] as string)
          : null,
      secretOrKey: configService.getOrThrow('JWT_TOKEN_SECRET')
    });
  }

  validate(payload: JwtPayload): JwtPayload {
    return payload;
  }
}
