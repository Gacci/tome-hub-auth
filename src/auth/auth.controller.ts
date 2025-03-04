import {
  Controller,
  Delete,
  Get,
  Post,
  Body,
  ParseIntPipe,
  Param,
  Patch,
  Request
} from '@nestjs/common';

import { ApiTags, ApiResponse } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/token-refresh.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

import { Public } from './decorators/public.decorator';
import { JwtPayloadPassport } from '../common/interfaces/jwt-payload-passport.interface';

import { ProfileDto } from './dto/profile.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('accounts/register')
  create(@Body() createAuthDto: RegisterAuthDto) {
    return this.auth.register(createAuthDto.email, createAuthDto.password);
  }

  @Public()
  @Post('accounts/login')
  login(@Body() loginAuthDto: LoginAuthDto) {
    return this.auth.login(loginAuthDto);
  }

  @Public()
  @Post('accounts/login/otp')
  sendLoginOtp(@Body() body: { email: string }) {
    return this.auth.sendLoginOtp(body.email);
  }

  @Get('accounts/:id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return new ProfileDto(await this.auth.findProfile(id));
  }

  @Patch('accounts/:id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateAuthDto: UpdateAuthDto
  ) {
    return this.auth.update(id, updateAuthDto);
  }

  @Delete('accounts/:id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.auth.remove(id);
  }

  @Public()
  @Post(['passwords/otp/send', 'password/otp/resend'])
  sendPasswordOtp(@Body() body: { email: string }) {
    return this.auth.sendPasswordResetOtp(body.email);
  }

  @Public()
  @Post('passwords/reset')
  @ApiResponse({ status: 200, description: 'Password reset successfully.' })
  resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.auth.resetPassword(resetPasswordDto);
  }

  @Post('password/:id')
  updatePassword(
    @Request() req: { user: JwtPayloadPassport },
    @Body() body: { newPassword: string }
  ) {
    return this.auth.updatePassword(req.user.sub, body.newPassword);
  }

  @Post('tokens/refresh')
  refreshTokens(
    @Request() req: { user: JwtPayloadPassport },
    @Body() body: RefreshTokenDto
  ) {
    return this.auth.updatePassword(req.user.sub, body.refreshToken);
  }

  @Delete('tokens/revoke')
  revokeTokens(
    @Request() req: { user: JwtPayloadPassport },
    @Body() body: RefreshTokenDto
  ) {
    return this.auth.revokeAccessToken(req.user.sub, body.refreshToken);
  }
}
