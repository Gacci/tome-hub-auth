import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/sequelize';

import { SessionToken } from './session-token.entity';

import { RedisService } from '../redis/redis.service';

import * as dayjs from 'dayjs';


export type JwtTokens = { accessToken: string; refreshToken: string };

@Injectable()
export class SessionTokenService {
  constructor(
    @InjectModel(SessionToken) private readonly sessions: typeof SessionToken,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly redis: RedisService
  ) {}

  private isTokenExpired(expiresAt: Date): boolean {
    return dayjs().isAfter(dayjs(expiresAt));
  }

  async addRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<SessionToken> {
    return await this.sessions.create({
      expiresAt: dayjs().add(7, 'day').toDate(),
      refreshToken,
      userId
    });
  }

  async validateRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<SessionToken> {
    if (await this.redis.getKey(refreshToken)) {
      throw new ForbiddenException('Token has been revoked.');
    }

    const session = await this.sessions.findOne({
      raw: true,
      where: { userId, refreshToken }
    });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token.');
    }

    if (this.isTokenExpired(session?.expiresAt)) {
      throw new ForbiddenException('Refresh token has expired.');
    }

    return session;
  }

  async removeRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<void> {
    const session = await this.sessions.findOne({
      where: { userId, refreshToken }
    });
    if (!session) {
      throw new BadRequestException('Refresh token not found.');
    }

    await this.redis.setKey(
      refreshToken,
      userId.toString(),
      dayjs(session.expiresAt).diff(dayjs(), 'seconds')
    );

    return await session.destroy();
  }

  async removeAllRefreshTokens(userId: number): Promise<number> {
    const sessions = await this.sessions.findAll({
      raw: true,
      where: { userId }
    });

    if (!sessions.length) {
      return 0;
    }

    for (const session of sessions) {
      await this.redis.setKey(
        session.refreshToken,
        userId.toString(),
        dayjs(session.expiresAt).diff(dayjs(), 'second')
      );
    }

    return await this.sessions.destroy({ where: { userId } });
  }

  async refreshToken(
    userId: number,
    refreshToken: string
  ): Promise<{ accessToken: string; refreshToken: string }> {
    if (!(await this.validateRefreshToken(userId, refreshToken))) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Generate new access & refresh tokens
    const newAccessToken = this.jwtService.sign(
      { sub: userId },
      { expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRES') }
    );
    const newRefreshToken = this.jwtService.sign(
      { sub: userId },
      { expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRES') }
    );

    // Store new refresh token and remove the old one
    await this.addRefreshToken(userId, newRefreshToken);
    await this.removeRefreshToken(userId, refreshToken);
    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async generateTokens(userId: number): Promise<JwtTokens> {
    const accessToken = this.jwtService.sign(
      { sub: userId },
      { expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRES') }
    );
    const refreshToken = this.jwtService.sign(
      { sub: userId },
      { expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRES') }
    );

    await this.addRefreshToken(userId, refreshToken);

    return { accessToken, refreshToken };
  }
}
