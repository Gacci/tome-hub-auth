import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

import { Request } from 'express';
import { Strategy } from 'passport-jwt';

import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';

export const ExtractRefreshJwtFromCookies = (req: Request): string | null => {
  return req.cookies.refresh_token
    ? (req.cookies.refresh_token as string)
    : null;
};

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh'
) {
  constructor(private readonly configService: ConfigService) {
    super({
      ignoreExpiration: false,
      jwtFromRequest: ExtractRefreshJwtFromCookies,
      secretOrKey: configService.getOrThrow('JWT_TOKEN_SECRET')
    });
  }

  validate(payload: JwtPayload): JwtPayload {
    console.log('JwtRefreshStrategy');
    return payload;
  }
}
