import {
  Body,
  Controller,
  Delete,
  FileTypeValidator,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  MaxFileSizeValidator,
  Param,
  ParseFilePipe,
  ParseIntPipe,
  Patch,
  Post,
  Request,
  UploadedFile,
  UseInterceptors
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiResponse, ApiTags } from '@nestjs/swagger';

import { SuccessResponse } from '../common/decorators/success-response.decorator';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { userProfileStorage } from '../common/storage/user-profile-storage';
import { AuthService } from './auth.service';
import { Public } from './decorators/public.decorator';
import { CredentialsDto } from './dto/credentials.dto';
import { LoginAuthDto } from './dto/login.dto';
import { ProfilePictureUrlDto } from './dto/profile-picture-url.dto';
import { ProfileDto } from './dto/profile.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { VerifyAccountDto } from './dto/verify-account.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('account/register')
  @SuccessResponse('Successfully uploaded profile image.')
  async create(@Body() createAuthDto: RegisterAuthDto) {
    await this.auth.register(createAuthDto.email, createAuthDto.password);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post(['account/register/otp/send', 'account/register/otp/resend'])
  @SuccessResponse(
    'You will receive an OTP if we are able to match you in our records.'
  )
  async sendRegisterOtp(@Body() body: { email: string }) {
    await this.auth.sendRegisterOtp(body.email);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('account/register/otp/verify')
  @SuccessResponse('You account has been successfully verified.')
  async verifyAccount(@Body() body: VerifyAccountDto) {
    await this.auth.verifyAccount(body);
  }

  @Public()
  @Post('account/login')
  @SuccessResponse('Login successful.')
  async login(@Body() loginAuthDto: LoginAuthDto) {
    return await this.auth.login(loginAuthDto);
  }

  @Public()
  @Post('account/login/otp/resend')
  @SuccessResponse('Check your inbox for your OTP.')
  async resendLoginOtp(@Body() loginAuthDto: CredentialsDto) {
    return this.auth.sendLoginOtp(loginAuthDto);
  }

  @Get('account/:id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return new ProfileDto(await this.auth.findProfile(id));
  }

  @Patch('account/:id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateAuthDto: UpdateAuthDto
  ) {
    return new ProfileDto(await this.auth.update(id, updateAuthDto));
  }

  @Delete('account/:id')
  @HttpCode(HttpStatus.OK)
  @SuccessResponse('Account deleted successfully')
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.auth.remove(id);
  }

  @Post('account/image')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(FileInterceptor('file', { storage: userProfileStorage }))
  async setProfilePicture(
    @Request() req: { user: JwtPayload },
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5000000 }),
          new FileTypeValidator({ fileType: 'image/jpeg' })
        ]
      })
    )
    uploaded: Express.Multer.File
  ) {
    return {
      data: new ProfilePictureUrlDto(
        await this.auth.update(+req.user.sub, {
          profilePictureUrl: uploaded.filename
        })
      ),
      message: 'Successfully uploaded profile image.'
    };
  }

  @Public()
  @Post(['password/otp/resend', 'password/otp/send'])
  @SuccessResponse('Check your inbox for your OTP.')
  async sendPasswordOtp(@Body() body: { email: string }) {
    await this.auth.sendPasswordResetOtp(body.email);
  }

  @Public()
  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @SuccessResponse('You password has been reset successfully.')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    await this.auth.resetPassword(resetPasswordDto);
  }

  @Post('password/:id')
  @HttpCode(HttpStatus.OK)
  @SuccessResponse('You password has been successfully changed.')
  async updatePassword(
    @Request() req: { user: JwtPayload },
    @Body() body: { newPassword: string }
  ) {
    await this.auth.updatePassword(+req.user.sub, body.newPassword);
  }

  @Post('token/access/refresh')
  async refreshTokens(@Request() req: { user: JwtPayload }) {
    return await this.auth.exchangeAccessToken(req.user);
  }

  @Delete('token/refresh/revoke')
  @HttpCode(HttpStatus.OK)
  @SuccessResponse('Refresh token has been successfully revoked.')
  async revokeTokens(@Request() req: { user: JwtPayload }) {
    await this.auth.revokeRefreshToken(req.user);
  }

  @Post('token/active')
  async active(@Headers('authorization') headers: { authorization: string }) {
    return {
      active: !(await this.auth.isTokenBlacklisted(
        headers.authorization.replace(/^Bearer\s/, '')
      ))
    };
  }
}
