import * as crypto from 'crypto';
import dayjs from 'dayjs';
import { Op } from 'sequelize';

import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/sequelize';

import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { MailerService } from '../mailer/mailer.service';
import { RedisService } from '../redis/redis.service';
import { User } from '../user/user.entity';
import { LoginAuthDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { VerifyAccountDto } from './dto/verify-account.dto';
import {
  SessionToken,
  TokenStatus,
  TokenType
} from './entities/session-token.entity';
import {CredentialsDto} from "./dto/credentials.dto";

// export type JwtPayload = { exp?: number; sub: number; ref: string; type?: TokenType; };
export type JwtTokens = { accessToken: string; refreshToken: string };

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService,
    private readonly redis: RedisService,
    @InjectModel(SessionToken) private readonly sessions: typeof SessionToken,
    @InjectModel(User) private readonly users: typeof User
  ) {}

  private generateOtp(size: number = 6) {
    return (parseInt(crypto.randomBytes(3).toString('hex'), 16) % 1_000_000)
      .toString()
      .padStart(size, '0');
  }

  private isOtpExpired(date: Date, seconds: number = 60) {
    return dayjs().utc().isAfter(dayjs(date).utc().add(seconds, 'second'));
  }

  private createAccessToken(payload: JwtPayload): string {
    return this.jwtService.sign(
      { ...payload, type: TokenType.ACCESS },
      {
        expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRES')
      }
    );
  }

  private createRefreshToken(payload: JwtPayload): string {
    return this.jwtService.sign(
      { ...payload, type: TokenType.REFRESH },
      {
        expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRES')
      }
    );
  }

  async register(email: string, password: string): Promise<void> {
    const user = await this.findByEmail(email);
    if (user) {
      throw new ConflictException('User already exists.');
    }

    const verifyAccountOtp = this.generateOtp(6);
    await this.mailer.notifySuccessfulRegistration(email, verifyAccountOtp);
    await this.users.create({ email, password, verifyAccountOtp });
  }

  async sendRegisterOtp(email: string): Promise<void> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (user.isAccountVerified) {
      throw new BadRequestException('User already verified.');
    }

    const verifyAccountOtp = this.generateOtp(6);
    await this.mailer.sendRegistrationOtp(email, verifyAccountOtp);
    await user.update({ verifyAccountOtp });
  }

  async verifyAccount(payload: VerifyAccountDto) {
    const user = await this.findByEmail(payload.email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!user.verifyAccountOtp) {
      throw new UnauthorizedException('Missing OTP');
    }

    if (
      !user.verifyAccountOtpIssuedAt ||
      this.isOtpExpired(user.verifyAccountOtpIssuedAt)
    ) {
      throw new BadRequestException('Verification OTP has expired.');
    }

    if (user.verifyAccountOtp !== payload.verifyAccountOtp) {
      throw new UnauthorizedException('Invalid OTP');
    }

    await user.update({
      isAccountVerified: true,
      verifyAccountOtp: null
    });
  }

  async login(credentials: LoginAuthDto): Promise<JwtTokens | null> {
    const user = await this.users.scope('fullDataView')
      .findOne({ where: { email: credentials.email } });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException(
        'Either password or username is incorrect.'
      );
    }

    if (user.is2faEnrolled) {
      if (!credentials.loginOtp) {
        const loginOtp = this.generateOtp(6);
        await this.mailer.sendLoginOtp(user.email, loginOtp);
        await user.update({ loginOtp });

        throw new UnauthorizedException('Login OTP required.');
      }

      if (!user.loginOtp || !user.loginOtpIssuedAt) {
        throw new UnauthorizedException('Invalid login token. Please request a new one.');
      }

      if (this.isOtpExpired(user.loginOtpIssuedAt)) {
        throw new BadRequestException('Login OTP has expired. Please request a new one.');
      }

      if (user.loginOtp !== credentials.loginOtp) {
        throw new UnauthorizedException('Invalid OTP');
      }

      await user.update({ loginOtp: null });
    }

    await this.mailer.notifySuccessfulLogin(user.email);
    return this.getSessionTokens(user.userId);
  }

  async sendLoginOtp(credentials: CredentialsDto): Promise<void> {
    const user = await this.users.scope('fullDataView')
      .findOne({ where: { email: credentials.email } });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException(
        'Either password or username is incorrect.'
      );
    }

    if (!user.is2faEnrolled) {
      throw new BadRequestException('User does not have 2FA enabled.');
    }

    const loginOtp = this.generateOtp(6);
    await this.mailer.sendLoginOtp(user.email, loginOtp);
    await user.update({ loginOtp });
  }

  async update(userId: number, update: UpdateAuthDto) {
    const user = await this.users.findByPk(userId);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    return await user.update(update);
  }

  async remove(userId: number) {
    const user = await this.users.findByPk(userId);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    return this.users.destroy({ where: { userId } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.users.findOne({ where: { email } });
  }

  async findByPk(userId: number): Promise<User | null> {
    return this.users.findByPk(userId);
  }

  async findProfile(userId: number): Promise<User | null> {
    return this.users.findByPk(userId, { raw: true });
  }

  async sendPasswordResetOtp(email: string): Promise<void> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    const resetPasswordOtp = this.generateOtp(6);
    await this.mailer.sendPasswordResetRequest(user.email, resetPasswordOtp);
    await user.update({ resetPasswordOtp });
  }

  async resetPassword(update: ResetPasswordDto): Promise<void> {
    const user = await this.findByEmail(update.email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (user.resetPasswordOtp !== update.resetPasswordOtp) {
      throw new UnauthorizedException('Invalid OTP.');
    }

    if (!user.resetPasswordOtpIssuedAt) {
      throw new BadRequestException('No OTP found.');
    }

    if (this.isOtpExpired(user.resetPasswordOtpIssuedAt)) {
      throw new ForbiddenException('OTP has expired or is invalid.');
    }

    if (await user.isSamePassword(update.newPassword)) {
      throw new BadRequestException('Password reuse not allowed.');
    }

    await this.mailer.notifyPasswordChanged(user.email);
    await user.update({
      password: update.newPassword,
      resetPasswordOtp: null
    });
  }

  async updatePassword(userId: number, password: string) {
    const user = await this.findByPk(userId);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (await user.isSamePassword(password)) {
      throw new BadRequestException('Password reuse not allowed.');
    }

    await this.mailer.notifyPasswordChanged(user.email);
    await user.update({ password });
  }

  async isTokenBlacklisted(jwtRawToken: string): Promise<string | null> {
    return await this.redis.getKey(jwtRawToken);
  }

  async revokeRefreshToken(decodedRefreshToken: JwtPayload): Promise<void> {
    if (TokenType.REFRESH !== decodedRefreshToken.type) {
      throw new UnauthorizedException(
        `Invalid token type ${decodedRefreshToken.type}`
      );
    }

    const sessions = await this.sessions.findAll({
      where: {
        createdAt: {
          [Op.gte]: dayjs(decodedRefreshToken.exp).utc().toDate()
        },
        familyId: decodedRefreshToken.ref,
        status: TokenStatus.ACTIVE,
        userId: decodedRefreshToken.sub
      }
    });

    for (const session of sessions) {
      const decoded = this.jwtService.decode<JwtPayload>(session.token);
      await session.update({ status: TokenStatus.REVOKED });
      await this.redis.setKey(
        session.token,
        session.userId.toString(),
        dayjs.unix(<number>decoded.exp).utc().diff(dayjs().utc(), 'second')
      );
    }
  }

  async exchangeAccessToken(decodedRefreshToken: JwtPayload) {
    if (TokenType.REFRESH !== decodedRefreshToken.type) {
      throw new UnauthorizedException('Refresh token required.');
    }

    await this.deactivateAccessToken(
      decodedRefreshToken,
      TokenStatus.EXCHANGED
    );

    const accessToken = this.createAccessToken({
      ref: decodedRefreshToken.ref,
      sub: decodedRefreshToken.sub
    });
    await this.sessions.create({
      familyId: decodedRefreshToken.ref,
      status: TokenStatus.ACTIVE,
      token: accessToken,
      type: TokenType.ACCESS,
      userId: +decodedRefreshToken.sub
    });

    return { accessToken };
  }

  async deactivateAccessToken(
    familyToken: JwtPayload,
    status: Exclude<TokenStatus, TokenStatus.ACTIVE> = TokenStatus.REVOKED
  ): Promise<void> {
    const session = await this.sessions.findOne({
      where: {
        createdAt: {
          [Op.gte]: dayjs.unix(<number>familyToken.iat).utc().toDate()
        },
        familyId: familyToken.ref,
        status: TokenStatus.ACTIVE,
        type: TokenType.ACCESS,
        userId: familyToken.sub
      }
    });

    if (!session) {
      throw new UnauthorizedException('No active session found.');
    }

    const decoded = this.jwtService.decode<JwtPayload>(session.token);
    if (TokenType.ACCESS !== decoded.type) {
      throw new UnauthorizedException('No access token found.');
    }

    await session.update({ status });
    await this.redis.setKey(
      session.token,
      session.userId.toString(),
      dayjs.unix(<number>decoded.exp).utc().diff(dayjs().utc(), 'seconds')
    );
  }

  async getSessionTokens(userId: number): Promise<JwtTokens> {
    const tokenRef = crypto.randomBytes(32).toString('hex');
    const accessToken = this.createAccessToken({ ref: tokenRef, sub: userId.toString() });
    const refreshToken = this.createRefreshToken({
      ref: tokenRef,
      sub: userId.toString()
    });

    await this.sessions.bulkCreate([
      {
        familyId: tokenRef,
        status: TokenStatus.ACTIVE,
        token: accessToken,
        type: TokenType.ACCESS,
        userId: userId
      },
      {
        familyId: tokenRef,
        status: TokenStatus.ACTIVE,
        token: refreshToken,
        type: TokenType.REFRESH,
        userId: userId
      }
    ]);

    return {
      accessToken,
      refreshToken
    };
  }
}
