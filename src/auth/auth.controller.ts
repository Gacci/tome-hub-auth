import {
  Controller,
  Get,
  Post,
  Body,
  ParseIntPipe,
  Param,
  Patch,
  Delete
} from '@nestjs/common';

import { ApiTags, ApiResponse } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

import { Public } from './decorators/public.decorator';

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
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.auth.findByPk(id);
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
}
