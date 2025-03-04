import { JwtPayload } from 'jsonwebtoken';
import { ExtractJwt, Strategy } from 'passport-jwt';

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

import { RedisService } from '../../redis/redis.service';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private auth: AuthService,
    private configService: ConfigService,
    private redisService: RedisService
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret) {
      throw new Error('Missing JWT_SECRET environment variable');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      passReqToCallback: true,
      secretOrKey: jwtSecret
    });
  }

  async validate(req: Request, payload: JwtPayload & { email: string }) {
    const jwtRawToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    console.log('Payload: ', payload, jwtRawToken);
    if (!payload || !jwtRawToken) {
      throw new UnauthorizedException('Token missing.');
    }

    if (await this.redisService.getKey(jwtRawToken)) {
      throw new UnauthorizedException('Token revoked.');
    }

    return payload;
  }
}
