import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';

import { InjectModel } from '@nestjs/sequelize';

import { MailerService } from '../mailer/mailer.service';
import {
  JwtTokens,
  SessionTokenService
} from '../user-session/session-token.service';

import { LoginAuthDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

import { User } from '../user/user.entity';

import * as dayjs from 'dayjs';
import * as crypto from 'crypto';
import { InferAttributes, NonNullFindOptions } from 'sequelize';


@Injectable()
export class AuthService {
  constructor(
    private readonly mailer: MailerService,
    private readonly sessions: SessionTokenService,
    @InjectModel(User) private readonly users: typeof User
  ) {}

  async register(email: string, password: string): Promise<User | null> {
    const user = await this.findByEmail(email);
    if (user) {
      throw new ConflictException('User already exists.');
    }

    return this.users.create({ email, password });
  }

  async login(credentials: LoginAuthDto): Promise<JwtTokens | null> {
    console.log(credentials);
    const user = await this.findByEmail(credentials.email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!(await user.isSamePassword(credentials.password))) {
      throw new BadRequestException(
        'Either password or username is incorrect.'
      );
    }

    // If 2FA is enabled, issue OTP first
    if (user.is2faEnrolled && !credentials.loginOtp) {
      await this.sendLoginOtp(user.email);
      throw new UnauthorizedException('Login OTP sent. Please verify.');
    }

    if (user.is2faEnrolled) {
      if (!user.loginOtp) {
        throw new UnauthorizedException('Missing OTP');
      }

      if (dayjs().isAfter(user.loginOtpExpiresAt)) {
        throw new BadRequestException('Login OTP has expired.');
      }

      if (user.loginOtp !== credentials.loginOtp) {
        throw new UnauthorizedException('Invalid OTP');
      }

      await user.update({ loginOtp: null, loginOtpExpiresAt: null });
    }

    // return user;
    return this.sessions.generateTokens(user.userId);
  }

  async sendLoginOtp(email: string): Promise<void> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (!user.is2faEnrolled) {
      throw new BadRequestException('User does not have 2FA enabled.');
    }

    // Generate a 6-digit OTP
    const loginOtp = (
      parseInt(crypto.randomBytes(3).toString('hex'), 16) % 1_000_000
    )
      .toString()
      .padStart(6, '0');

    // Set OTP expiration time (e.g., 5 minutes)
    const loginOtpExpiresAt = dayjs().add(5, 'minutes').toDate();

    // Store OTP (consider hashing it for security)
    await user.update({ loginOtp, loginOtpExpiresAt });

    // Send OTP via email
    await this.mailer.sendOtpEmail(email, loginOtp);
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

    return this.users.update(
      { deletedAt: dayjs().toDate() },
      { where: { userId } }
    );
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

    // OTP expires in 1 minute
    const resetPasswordOtpExpiresAt = dayjs().add(1, 'minutes').toDate();

    // 6-digit OTP
    const resetPasswordOtp = (
      parseInt(crypto.randomBytes(3).toString('hex'), 16) % 1_000_000
    )
      .toString()
      .padStart(6, '0');

    await user.update({ resetPasswordOtp, resetPasswordOtpExpiresAt });
    await this.mailer.sendOtpEmail(email, resetPasswordOtp);
  }

  async resetPassword(update: ResetPasswordDto): Promise<void> {
    const user = await this.findByEmail(update.email);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (user.resetPasswordOtp !== update.resetPasswordOtp) {
      throw new UnauthorizedException('Invalid OTP.');
    }

    if (!user.resetPasswordOtpExpiresAt) {
      throw new BadRequestException('No OTP found.');
    }

    if (dayjs().isAfter(dayjs(user.resetPasswordOtpExpiresAt))) {
      throw new ForbiddenException('OTP has expired or is invalid.');
    }

    if (await user.isSamePassword(update.newPassword)) {
      throw new BadRequestException('Password reuse not allowed.');
    }

    // Hash new password and update user
    await user.update({
      password: update.newPassword,
      resetPasswordOtp: null,
      resetPasswordOtpExpiresAt: null
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

    return await user.update({ password });
  }

  async revokeAccessToken(userId: number, refreshToken: string) {
    return this.sessions.removeRefreshToken(userId, refreshToken);
  }
}
