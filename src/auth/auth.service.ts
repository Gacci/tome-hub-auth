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

import * as crypto from 'crypto';
import dayjs from 'dayjs';
import { Op } from 'sequelize';

import { CollegesService } from '../colleges/colleges.service';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { MailerService } from '../mailer/mailer.service';
import { RabbitMQService, RoutingKey } from '../rabbit-mq/rabbit-mq.service';
import { RedisService } from '../redis/redis.service';
import { User } from '../user/user.model';
import { CredentialsDto } from './dto/credentials.dto';
import { LoginAuthDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { VerifyAccountDto } from './dto/verify-account.dto';
import {
  SessionToken,
  TokenStatus,
  TokenType
} from './models/session-token.model';

// export type JwtPayload = { exp?: number; sub: number; ref: string; type?: TokenType; };
export type JwtTokens = { jwtAccessToken: string; jwtRefreshToken: string };
export type JwtStatus = { blacklisted: boolean; type: TokenType };

// const Pluck = <T, K extends keyof T>(obj: T, key: K) => obj[key];

@Injectable()
export class AuthService {
  constructor(
    private readonly collegesService: CollegesService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService,
    private readonly rabbitMQService: RabbitMQService,
    private readonly redis: RedisService,
    @InjectModel(SessionToken) private readonly sessions: typeof SessionToken,
    @InjectModel(User) private readonly users: typeof User
  ) {}
  private generateRandomChars(size: number = 32): string {
    return crypto
      .randomBytes(size / 2)
      .toString('hex')
      .padStart(size, '0');
  }

  private generateOtp(size: number = 6) {
    return (
      parseInt(crypto.randomBytes(size / 2).toString('hex'), 16) % 1_000_000
    )
      .toString()
      .padStart(size, '0');
  }

  private isOtpExpired(date: Date, seconds: number = 60) {
    return dayjs().utc().isAfter(dayjs(date).utc().add(seconds, 'second'));
  }

  async getSessionTokens(user: User): Promise<JwtTokens> {
    const tokenRef = crypto.randomBytes(32).toString('hex');
    const jwtAccessToken = this.createAccessToken({
      ref: tokenRef,
      scope: user.collegeId,
      sub: user.userId,
      verified: user.isAccountVerified
    });
    const jwtRefreshToken = this.createRefreshToken({
      ref: tokenRef,
      scope: user.collegeId,
      sub: user.userId,
      verified: user.isAccountVerified
    });

    await this.sessions.bulkCreate([
      {
        familyId: tokenRef,
        status: TokenStatus.ACTIVE,
        token: jwtAccessToken,
        type: TokenType.ACCESS,
        userId: user.userId
      },
      {
        familyId: tokenRef,
        status: TokenStatus.ACTIVE,
        token: jwtRefreshToken,
        type: TokenType.REFRESH,
        userId: user.userId
      }
    ]);

    return {
      jwtAccessToken,
      jwtRefreshToken
    };
  }

  private createAccessToken(payload: JwtPayload): string {
    return this.jwtService.sign(
      { ...payload, type: TokenType.ACCESS },
      {
        expiresIn: +this.configService.get('JWT_ACCESS_TOKEN_EXPIRES')
      }
    );
  }

  private createRefreshToken(payload: JwtPayload): string {
    return this.jwtService.sign(
      { ...payload, type: TokenType.REFRESH },
      {
        expiresIn: +this.configService.get('JWT_REFRESH_TOKEN_EXPIRES')
      }
    );
  }

  async register(email: string, password: string): Promise<void> {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException(
        'Email not valid, academic email required.'
      );
    }

    const existing = await this.findByEmail(email);
    if (existing) {
      throw new ConflictException('User already exists.');
    }

    const verifyAccountOtp = this.generateOtp(6);
    const inserted = await this.users.create({
      email,
      password,
      verifyAccountOtp
    });

    await this.mailer.notifySuccessfulRegistration(email, verifyAccountOtp);
    this.rabbitMQService.publish<Partial<User>>(RoutingKey.USER_REGISTRATION, {
      createdAt: inserted.createdAt as Date,
      email: inserted.email,
      updatedAt: inserted.updatedAt as Date,
      userId: inserted.userId
    });
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
    if (!(await this.collegesService.emailDomainExists(payload.email))) {
      throw new BadRequestException(
        'Email not valid, academic email required.'
      );
    }

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

    const updated = await user.update({
      isAccountVerified: true,
      verifyAccountOtp: null
    });

    this.rabbitMQService.publish(RoutingKey.USER_UPDATE, {
      isAccountVerified: updated.isAccountVerified,
      userId: updated.userId
    });
  }

  async login(credentials: LoginAuthDto): Promise<JwtTokens | null> {
    if (!(await this.collegesService.emailDomainExists(credentials.email))) {
      throw new BadRequestException(
        'Email not valid, academic email required.'
      );
    }

    const user = await this.users.findOneWithPassword({
      email: credentials.email
    });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!user.isAccountVerified) {
      throw new UnauthorizedException('Your account is not verified.');
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException(
        'Either password or username is incorrect.'
      );
    }

    if (user.is2faEnabled) {
      if (!credentials.loginOtp) {
        const loginOtp = this.generateOtp(6);
        await this.mailer.sendLoginOtp(user.email, loginOtp);
        await user.update({ loginOtp });

        throw new ForbiddenException('Login OTP required.');
      }

      if (!user.loginOtp || !user.loginOtpIssuedAt) {
        throw new BadRequestException(
          'Invalid login token. Please request a new one.'
        );
      }

      if (this.isOtpExpired(user.loginOtpIssuedAt)) {
        throw new BadRequestException(
          'Login OTP has expired. Please request a new one.'
        );
      }

      if (user.loginOtp !== credentials.loginOtp) {
        throw new UnauthorizedException('Invalid OTP');
      }

      await user.update({ loginOtp: null });
    }

    await this.mailer.notifySuccessfulLogin(user.email);
    return this.getSessionTokens(user);
  }

  async sendLoginOtp(credentials: CredentialsDto): Promise<void> {
    const user = await this.users.findOneWithPassword({
      email: credentials.email
    });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException(
        'Either password or username is incorrect.'
      );
    }

    if (!user.is2faEnabled) {
      throw new BadRequestException('User does not have 2FA enabled.');
    }

    const loginOtp = this.generateOtp(6);
    await this.mailer.sendLoginOtp(user.email, loginOtp);
    await user.update({ loginOtp });
  }

  async update(userId: number, update: UpdateAuthDto) {
    const existing = await this.users.findByPk(userId);
    if (!existing) {
      throw new NotFoundException('User not found.');
    }

    const user = await existing.update(update);
    this.rabbitMQService.publish(
      RoutingKey.USER_UPDATE,
      Object.fromEntries(
        [...Object.keys(update), 'updatedAt', 'userId'].map(
          (k: keyof typeof update) => [k, user[k as keyof typeof user]]
        )
      )
    );

    return user;
  }

  async remove(userId: number) {
    const user = await this.users.findByPk(userId);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    const { deletedAt } = await user.update({ deletedAt: dayjs().utc() });
    this.rabbitMQService.publish(RoutingKey.USER_UPDATE, {
      deletedAt,
      userId
    });

    return !!deletedAt;
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

  async sendResetPasswordOtp(email: string): Promise<void> {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException(
        'Email not valid, academic email required.'
      );
    }

    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    const resetPasswordOtp = this.generateOtp(6);
    // await this.mailer.sendPasswordResetRequest(user.email, resetPasswordOtp);
    await user.update({
      resetPasswordOtp,
      resetPasswordToken: null,
      resetPasswordTokenIssuedAt: null
    });
  }

  async verifyResetPasswordOtp(email: string, resetPasswordOtp: string) {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException(
        'Email not valid, academic email required.'
      );
    }

    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    console.log(email, resetPasswordOtp, user.email, user.resetPasswordOtp);
    if (user.resetPasswordOtp !== resetPasswordOtp) {
      throw new BadRequestException('OTP is invalid.');
    }

    if (
      !user.resetPasswordOtpIssuedAt ||
      this.isOtpExpired(user.resetPasswordOtpIssuedAt)
    ) {
      throw new ForbiddenException('OTP has expired or is invalid.');
    }

    const resetPasswordToken = this.generateRandomChars(32);
    await user.update({ resetPasswordOtp: null, resetPasswordToken });

    return { resetPasswordToken };
  }

  async resetPassword(update: ResetPasswordDto): Promise<void> {
    const user = await this.users.findOneWithPassword({ email: update.email });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (user.resetPasswordToken !== update.resetPasswordToken) {
      throw new UnauthorizedException('Invalid OTP.');
    }

    if (
      !user.resetPasswordTokenIssuedAt ||
      this.isOtpExpired(user.resetPasswordTokenIssuedAt)
    ) {
      throw new ForbiddenException('OTP has expired or is invalid.');
    }

    if (await user.isSamePassword(update.newPassword)) {
      throw new BadRequestException('Password reuse not allowed.');
    }

    await this.mailer.notifyPasswordChanged(user.email);
    await user.update({
      password: update.newPassword,
      resetPasswordOtp: null,
      resetPasswordToken: null
    });
  }

  async updatePassword(userId: number, password: string) {
    const user = await this.users.findOneWithPassword({ userId });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (await user.isSamePassword(password)) {
      throw new BadRequestException('Password reuse not allowed.');
    }

    await user.update({ password });
    await this.mailer.notifyPasswordChanged(user.email);
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
          [Op.gte]: dayjs
            .unix(decodedRefreshToken.exp as number)
            .utc()
            .toDate()
        },
        familyId: decodedRefreshToken.ref,
        status: TokenStatus.ACTIVE,
        userId: decodedRefreshToken.sub
      }
    });

    // await this.redis.setKey(
    //   refres,
    //   session.userId.toString(),
    //   dayjs
    //     .unix(decoded.exp as number)
    //     .utc()
    //     .diff(dayjs().utc(), 'second')
    // );

    for (const session of sessions) {
      const decoded = this.jwtService.decode<JwtPayload>(session.token);
      this.rabbitMQService.publish(
        RoutingKey.TOKEN_REFRESH_REVOKE,
        session.token
      );

      await session.update({ status: TokenStatus.REVOKED });
      await this.redis.setKey(
        session.token,
        session.userId.toString(),
        dayjs
          .unix(decoded.exp as number)
          .utc()
          .diff(dayjs().utc(), 'second')
      );
    }
  }

  async exchangeAccessToken(decodedRefreshToken: JwtPayload) {
    if (TokenType.REFRESH !== decodedRefreshToken.type) {
      throw new UnauthorizedException('Refresh token required.');
    }

    if (!(await this.users.exists({ userId: +decodedRefreshToken.sub }))) {
      throw new BadRequestException('User no longer exists.');
    }

    await this.deactivateAccessToken(
      decodedRefreshToken,
      TokenStatus.EXCHANGED
    );

    const jwtAccessToken = this.createAccessToken({
      ref: decodedRefreshToken.ref,
      scope: decodedRefreshToken.scope,
      sub: decodedRefreshToken.sub,
      verified: decodedRefreshToken.verified
    });
    await this.sessions.create({
      familyId: decodedRefreshToken.ref,
      status: TokenStatus.ACTIVE,
      token: jwtAccessToken,
      type: TokenType.ACCESS,
      userId: +decodedRefreshToken.sub
    });

    return jwtAccessToken;
  }

  async deactivateAccessToken(
    familyToken: JwtPayload,
    status: Exclude<TokenStatus, TokenStatus.ACTIVE> = TokenStatus.REVOKED
  ): Promise<boolean> {
    const session = await this.sessions.findOne({
      where: {
        createdAt: {
          [Op.gte]: dayjs
            .unix(familyToken.iat as number)
            .utc()
            .toDate()
        },
        familyId: familyToken.ref,
        status: TokenStatus.ACTIVE,
        type: TokenType.ACCESS,
        userId: familyToken.sub
      }
    });

    if (!session) {
      return false;
    }

    const decoded = this.jwtService.decode<JwtPayload>(session.token);
    this.rabbitMQService.publish(RoutingKey.TOKEN_ACCESS_REVOKE, session.token);

    await session.update({ status });
    await this.redis.setKey(
      session.token,
      session.userId.toString(),
      dayjs
        .unix(decoded.exp as number)
        .utc()
        .diff(dayjs().utc(), 'second')
    );

    return true;
  }
}
