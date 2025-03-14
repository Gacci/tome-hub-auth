import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

import { Request } from 'express';
import { Strategy } from 'passport-jwt';

import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';

export const ExtractAccessJwtFromCookies = (req: Request): string | null => {
  return req.cookies.access_token ? (req.cookies.access_token as string) : null;
};

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(
  Strategy,
  'jwt-access'
) {
  constructor(private readonly configService: ConfigService) {
    super({
      ignoreExpiration: false,
      jwtFromRequest: ExtractAccessJwtFromCookies,
      secretOrKey: configService.getOrThrow('JWT_TOKEN_SECRET')
    });
  }

  validate(payload: JwtPayload): JwtPayload {
    console.log('JwtAccessStrategy');
    return payload;
  }
}
