import {
  ForbiddenException,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';

import { TokenType, SessionToken } from './session-token.entity';

import * as dayjs from 'dayjs';
import { InjectModel } from '@nestjs/sequelize';

export type JwtTokens = { accessToken: string; refreshToken: string };

@Injectable()
export class SessionTokenService {
  constructor(
    @InjectModel(SessionToken) private readonly sessions: typeof SessionToken,
    private readonly jwtService: JwtService
  ) {}
  async addRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<SessionToken> {
    return await this.sessions.create({
      expiresAt: dayjs().add(7, 'day').toDate(),
      refreshToken,
      typeOfToken: TokenType.REFRESH,
      userId
    });
  }

  async validateRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<SessionToken> {
    const session = await this.sessions.findOne({
      raw: true,
      where: { userId, refreshToken }
    });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token.');
    }

    if (dayjs().isAfter(dayjs(session?.expiresAt))) {
      throw new ForbiddenException('Refresh token has expired.');
    }

    return session;
  }

  async removeRefreshToken(
    userId: number,
    refreshToken: string
  ): Promise<void> {
    await this.sessions.update(
      {
        deletedAt: dayjs().toDate()
      },
      {
        where: { userId, refreshToken }
      }
    );
  }

  async removeAllRefreshTokens(userId: number): Promise<void> {
    await this.sessions.destroy({
      where: { userId }
    });
  }

  async refreshToken(
    userId: number,
    refreshToken: string
  ): Promise<{ accessToken: string; refreshToken: string }> {
    if (!(await this.validateRefreshToken(userId, refreshToken))) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Generate new access & refresh tokens
    const newAccessToken = this.jwtService.sign({ userId });
    const newRefreshToken = this.jwtService.sign(
      { userId },
      { expiresIn: '7d' }
    );

    // Store new refresh token and remove the old one
    await this.addRefreshToken(userId, newRefreshToken);
    await this.removeRefreshToken(userId, refreshToken);
    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async generateTokens(userId: number): Promise<JwtTokens> {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign({ userId }, { expiresIn: '7d' });

    await this.addRefreshToken(userId, refreshToken);

    return { accessToken, refreshToken };
  }
}
