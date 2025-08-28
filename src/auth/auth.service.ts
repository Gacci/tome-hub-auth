import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/sequelize';

import { AwsConfigService, S3Bucket } from '@/aws/aws-config.service';
import { CollegesService } from '@/colleges/colleges.service';
import { JwtPayload } from '@/common/interfaces/jwt-payload.interface';
import { MailerService } from '@/mailer/mailer.service';
import { RabbitMQService, RoutingKey } from '@/rabbit-mq/rabbit-mq.service';
import { RedisService } from '@/redis/redis.service';
import { User } from '@/user/user.model';

import * as crypto from 'crypto';
import dayjs from 'dayjs';
import { Op } from 'sequelize';

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

export type JwtTokens = { jwtAccessToken: string; jwtRefreshToken: string };
export type JwtStatus = { blacklisted: boolean; type: TokenType };

// const Pluck = <T, K extends keyof T>(obj: T, key: K) => obj[key];

@Injectable()
export class AuthService {
  constructor(
    private readonly awsS3Service: AwsConfigService,
    private readonly collegesService: CollegesService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService,
    private readonly rabbitMQService: RabbitMQService,
    @Inject('REDIS_AUTH_REFRESH_REVOKED') private readonly redis: RedisService,
    @InjectModel(SessionToken) private readonly sessions: typeof SessionToken,
    @InjectModel(User) private readonly users: typeof User
  ) {}
  async register(email: string, password: string): Promise<void> {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException({
        error: 'EmailError',
        message: 'Email is not valid, an academic email required'
      });
    }

    const existing = await this.findByEmail(email);
    if (existing) {
      throw new ConflictException({
        error: 'UserError',
        message: 'User already exists'
      });
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
      membership: inserted.membership,
      membershipExpiresAt: inserted.membershipExpiresAt,
      updatedAt: inserted.updatedAt as Date,
      userId: inserted.userId
    });
  }

  async sendRegisterOtp(email: string) {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (user.isAccountVerified) {
      throw new ConflictException({
        error: 'UserVerified',
        message: 'Account had already been verified'
      });
    }

    const verifyAccountOtp = this.generateOtp(6);
    await this.mailer.sendRegistrationOtp(email, verifyAccountOtp);
    await user.update({ verifyAccountOtp });
  }

  async verifyAccount(payload: VerifyAccountDto) {
    if (!(await this.collegesService.emailDomainExists(payload.email))) {
      throw new BadRequestException({
        error: 'EmailError',
        message: 'Email is not valid, an academic email required'
      });
    }

    const user = await this.findByEmail(payload.email);
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (user.isAccountVerified) {
      throw new ConflictException({
        error: 'UserVerified',
        message: 'Account had already been verified'
      });
    }

    if (!user.verifyAccountOtp || !user.verifyAccountOtpIssuedAt) {
      throw new UnauthorizedException({
        error: 'OTPError',
        message: 'Account verification OTP has not been issued'
      });
    }

    if (this.isOtpExpired(user.verifyAccountOtpIssuedAt)) {
      throw new BadRequestException({
        error: 'OTPError',
        message: 'Account verification OTP has expired'
      });
    }

    if (user.verifyAccountOtp !== payload.verifyAccountOtp) {
      throw new UnauthorizedException({
        error: 'OTPError',
        message: 'Account verification OTP is invalid'
      });
    }

    const updated = await user.update({
      isAccountVerified: true,
      verifyAccountOtp: null
    });

    this.rabbitMQService.publish(RoutingKey.USER_UPDATE, {
      isAccountVerified: updated.isAccountVerified,
      // membership: updated.membership,
      // membershipExpiresAt: updated.membershipExpiresAt,
      userId: updated.userId
    });
  }

  async login(credentials: LoginAuthDto): Promise<JwtTokens | null> {
    if (!(await this.collegesService.emailDomainExists(credentials.email))) {
      throw new BadRequestException({
        error: 'EmailError',
        message: 'Email is not valid, an academic email is required'
      });
    }

    const user = await this.users.findOneWithPassword({
      email: credentials.email
    });
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException({
        error: 'CredentialsError',
        message: 'Either password or username is incorrect'
      });
    }

    if (user.is2faEnabled) {
      if (!credentials.loginOtp) {
        const loginOtp = this.generateOtp(6);
        await this.mailer.sendLoginOtp(user.email, loginOtp);
        await user.update({ loginOtp });

        throw new ForbiddenException({
          error: 'OTPError',
          message: 'Login OTP is required'
        });
      }

      if (!user.loginOtp || !user.loginOtpIssuedAt) {
        throw new BadRequestException({
          error: 'OTPError',
          message: 'Login OTP has not been issued.'
        });
      }

      if (this.isOtpExpired(user.loginOtpIssuedAt)) {
        throw new BadRequestException({
          error: 'OTPError',
          message: 'Login OTP has expired. Please request a new one.'
        });
      }

      if (user.loginOtp !== credentials.loginOtp) {
        throw new UnauthorizedException({
          error: 'OTPError',
          message: 'Login OTP is invalid'
        });
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
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException({
        error: 'CredentialsError',
        message: 'Either password or username is incorrect'
      });
    }

    if (!user.is2faEnabled) {
      throw new BadRequestException({
        error: 'UserError',
        message: 'User does not have 2FA enabled'
      });
    }

    const loginOtp = this.generateOtp(6);
    await this.mailer.sendLoginOtp(user.email, loginOtp);
    await user.update({ loginOtp });
  }

  async update(userId: number, update: UpdateAuthDto) {
    const existing = await this.users.findByPk(userId);
    if (!existing) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    const user = await existing.update(update);
    this.rabbitMQService.publish(
      RoutingKey.USER_UPDATE,
      Object.fromEntries(
        ['updatedAt', 'userId']
          .concat(Object.keys(update))
          .map((k: keyof typeof update) => [k, user[k as keyof typeof user]])
      )
    );

    return user;
  }

  async updateProfilePicture(userId: number, file: Express.Multer.File) {
    const key = file
      ? await this.awsS3Service.upload(S3Bucket.PROFILES, file)
      : null;

    return await this.update(userId, {
      profilePictureUrl: key
    });
  }

  async remove(userId: number) {
    const user = await this.users.findByPk(userId);
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
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

  async findProfile(userId: number): Promise<User | null> {
    return this.users.findByPk(userId);
  }

  async sendResetPasswordOtp(email: string): Promise<void> {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException({
        error: 'CredentialsError',
        message: 'Either password or username is incorrect'
      });
    }

    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    const resetPasswordOtp = this.generateOtp(6);
    // await this.mailer.sendPasswordResetRequest(users.email, resetPasswordOtp);
    await user.update({
      resetPasswordOtp,
      resetPasswordToken: null,
      resetPasswordTokenIssuedAt: null
    });
  }

  async verifyResetPasswordOtp(email: string, resetPasswordOtp: string) {
    if (!(await this.collegesService.emailDomainExists(email))) {
      throw new BadRequestException({
        error: 'CredentialsError',
        message: 'Either password or username is incorrect'
      });
    }

    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (!user.resetPasswordOtp || !user.resetPasswordOtpIssuedAt) {
      throw new BadRequestException({
        error: 'PasswordError',
        message: 'Password reset OTP has not been issued'
      });
    }

    if (this.isOtpExpired(user.resetPasswordOtpIssuedAt)) {
      throw new ForbiddenException({
        error: 'PasswordError',
        message: 'Password reset OTP is expired or invalid'
      });
    }

    if (user.resetPasswordOtp !== resetPasswordOtp) {
      throw new BadRequestException({
        error: 'PasswordError',
        message: 'Password reset OTP is invalid'
      });
    }

    const resetPasswordToken = this.generateRandomChars(6);
    await user.update({ resetPasswordOtp: null, resetPasswordToken });

    return { resetPasswordToken };
  }

  async resetPassword(update: ResetPasswordDto): Promise<void> {
    const user = await this.users.findOneWithPassword({ email: update.email });
    if (!user) {
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (user.resetPasswordToken !== update.resetPasswordToken) {
      throw new UnauthorizedException({
        error: 'PasswordError',
        message: 'Password reset OTP is invalid'
      });
    }

    if (!user.resetPasswordTokenIssuedAt) {
      throw new BadRequestException({
        error: 'PasswordError',
        message: 'Password reset OTP has not been issued'
      });
    }

    if (this.isOtpExpired(user.resetPasswordTokenIssuedAt)) {
      throw new ForbiddenException({
        error: 'PasswordError',
        message: 'Password reset OTP has expired'
      });
    }

    if (await user.isSamePassword(update.newPassword)) {
      throw new BadRequestException({
        error: 'PasswordError',
        message: 'Password reuse is not allowed'
      });
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
      throw new NotFoundException({
        error: 'UserError',
        message: 'User could not be located'
      });
    }

    if (await user.isSamePassword(password)) {
      throw new BadRequestException({
        error: 'PasswordError',
        message: 'Password reuse is not allowed'
      });
    }

    await user.update({ password });
    await this.mailer.notifyPasswordChanged(user.email);
  }

  async revokeRefreshToken(decodedRefreshToken: JwtPayload): Promise<void> {
    if (TokenType.REFRESH !== decodedRefreshToken.type) {
      throw new UnauthorizedException({
        error: 'TokenError',
        message: `Invalid token of type '${decodedRefreshToken.type}'`
      });
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
      throw new UnauthorizedException({
        error: 'TokenError',
        message: `Expects token of type '${decodedRefreshToken.type}'`
      });
    }

    const user = await this.users.findByPk(decodedRefreshToken.sub);
    if (!user) {
      throw new BadRequestException({
        error: 'UserError',
        message: 'Account is no longer active'
      });
    }

    await this.deactivateAccessToken(
      decodedRefreshToken,
      TokenStatus.EXCHANGED
    );

    console.log('exchangeAccessToken', user);
    const jwtAccessToken = this.createAccessToken({
      mbr: user.membership,
      mex: user.membershipExpiresAt?.getTime(),
      ref: decodedRefreshToken.ref,
      scope: user.collegeId,
      sub: user.userId,
      verified: user.isAccountVerified
    });

    await this.sessions.create({
      familyId: decodedRefreshToken.ref,
      status: TokenStatus.ACTIVE,
      token: jwtAccessToken,
      type: TokenType.ACCESS,
      userId: user.userId
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
    const jwtTokenPayload = {
      mbr: user.membership,
      mex: user.membershipExpiresAt?.getTime(),
      ref: tokenRef,
      scope: user.collegeId,
      sub: user.userId,
      verified: user.isAccountVerified
    };

    const jwtAccessToken = this.createAccessToken(jwtTokenPayload);
    const jwtRefreshToken = this.createRefreshToken(jwtTokenPayload);

    const sessionRecordPayload = {
      familyId: tokenRef,
      status: TokenStatus.ACTIVE,
      token: jwtAccessToken,
      type: TokenType.ACCESS,
      userId: user.userId
    };

    await this.sessions.bulkCreate([
      {
        ...sessionRecordPayload,
        type: TokenType.ACCESS
      },
      {
        ...sessionRecordPayload,
        type: TokenType.REFRESH
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
}
