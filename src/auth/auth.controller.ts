import {
  Body,
  Controller,
  Delete,
  FileTypeValidator,
  Get,
  HttpCode,
  HttpStatus,
  MaxFileSizeValidator,
  Param,
  ParseFilePipe,
  ParseIntPipe,
  Patch,
  Post,
  Req,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiResponse, ApiTags } from '@nestjs/swagger';

import { CookieOptions, Response } from 'express';

import { AwsConfigService, S3Bucket } from '../aws/aws-config.service';
import { SuccessResponse } from '../common/decorators/success-response.decorator';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { CheckUserAccessGuard } from '../guards/user-access/check-user-access.guard';
// import { userProfileStorage } from '../common/storage/user-profile-storage';
import { AuthService } from './auth.service';
import { CredentialsDto } from './dto/credentials.dto';
import { EmailDto } from './dto/email.dto';
import { LoginAuthDto } from './dto/login.dto';
import { ProfilePictureUrlDto } from './dto/profile-picture-url.dto';
import { ProfileDto } from './dto/profile.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { VerifyAccountDto } from './dto/verify-account.dto';
import { JwtAuthAccessGuard } from './guards/jwt-auth-access/jwt-auth-access.guard';
import { JwtAuthRefreshGuard } from './guards/jwt-auth-refresh/jwt-auth-refresh.guard';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly awsConfigService: AwsConfigService,
    private readonly configService: ConfigService
  ) {}

  @Post('account/register')
  @ApiResponse({
    description: 'Registers a new user',
    status: HttpStatus.CREATED
  })
  @SuccessResponse('Successfully created account.')
  async create(@Body() createAuthDto: RegisterAuthDto) {
    await this.auth.register(createAuthDto.email, createAuthDto.password);
  }

  @HttpCode(HttpStatus.OK)
  @Post('account/register/otp/resend')
  @ApiResponse({
    description: 'Emails an OTP for user to confirm registration.',
    status: HttpStatus.OK
  })
  @SuccessResponse(
    'You will receive an OTP if we are able to match you in our records.'
  )
  async sendRegisterOtp(@Body() body: EmailDto) {
    await this.auth.sendRegisterOtp(body.email);
  }

  @HttpCode(HttpStatus.OK)
  @Post('account/verify')
  @ApiResponse({
    description: 'Verifies OTP for user to confirm registration.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You account has been successfully verified.')
  async verifyAccount(@Body() body: VerifyAccountDto) {
    await this.auth.verifyAccount(body);
  }

  @Post('account/login')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    description:
      'Grants access to user (requires OTP if user is enrolled in 2FA authentication).',
    status: HttpStatus.OK
  })
  @SuccessResponse('Login successful.')
  async login(
    @Res({ passthrough: true }) res: Response,
    @Body() loginAuthDto: LoginAuthDto
  ) {
    const tokens = await this.auth.login(loginAuthDto);
    const isProdEnv = ['prod', 'production'].includes(
      this.configService.get<string>('NODE_ENV', '')
    );

    const options: CookieOptions = {
      httpOnly: isProdEnv,
      sameSite: 'none',
      secure: isProdEnv
    };

    res.cookie('access_token', tokens?.jwtAccessToken, {
      ...options,
      maxAge: 1000 * +this.configService.get('JWT_ACCESS_TOKEN_EXPIRES')
    });
    res.cookie('refresh_token', tokens?.jwtRefreshToken, {
      ...options,
      maxAge: 1000 * +this.configService.get('JWT_REFRESH_TOKEN_EXPIRES')
    });
  }

  @Post('account/login/otp/resend')
  @ApiResponse({ description: 'Sends login OTP.', status: HttpStatus.OK })
  @SuccessResponse('Check your inbox for your OTP.')
  async resendLoginOtp(@Body() loginAuthDto: CredentialsDto) {
    return this.auth.sendLoginOtp(loginAuthDto);
  }

  @Get('account/:id')
  @UseGuards(JwtAuthAccessGuard)
  @ApiResponse({
    description: 'Reads user profile specified by `id`',
    status: HttpStatus.OK
  })
  @SuccessResponse('Success')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return new ProfileDto(await this.auth.findProfile(id));
  }

  @Patch('account/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  // @CheckUserAccess({ withLocalKey: 'subs', withRequestKey: 'id' })
  @ApiResponse({
    description: 'Updates user specified by `id`',
    status: HttpStatus.OK
  })
  @SuccessResponse('Success')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateAuthDto: UpdateAuthDto
  ) {
    return new ProfileDto(await this.auth.update(id, updateAuthDto));
  }

  @Delete('account/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  @ApiResponse({
    description: 'Deletes user specified by `id`',
    status: HttpStatus.OK
  })
  @SuccessResponse('Account deleted successfully.')
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.auth.remove(id);
  }

  @Post('account/image')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard)
  @ApiResponse({
    description: 'Updates profile image for authenticated user.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Successfully uploaded profile image.')
  @UseInterceptors(FileInterceptor('file')) // { storage: userProfileStorage }
  async setProfilePicture(
    @Req() req: { user: JwtPayload },
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 1024 * 1024 * 2 }),
          new FileTypeValidator({ fileType: 'image/jpeg' })
        ]
      })
    )
    uploaded: Express.Multer.File
  ) {
    const response = await this.awsConfigService.upload(
      S3Bucket.PROFILES,
      uploaded
    );

    new ProfilePictureUrlDto(
      await this.auth.update(+req.user.sub, {
        // profilePictureUrl: uploaded.filename
        profilePictureUrl: response.filename
      })
    );
  }

  @Post('password/reset/otp/send')
  @ApiResponse({
    description: 'Sends password reset OTP.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Check your inbox for your OTP.')
  async sendPasswordOtp(@Body() body: EmailDto) {
    await this.auth.sendPasswordResetOtp(body.email);
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard)
  @ApiResponse({
    description: 'Resets password for user providing OTP.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You password has been reset successfully.')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    await this.auth.resetPassword(resetPasswordDto);
  }

  @Post('password/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  @ApiResponse({
    description: 'Resets password for user specified by `id`.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You password has been successfully changed.')
  async updatePassword(
    @Req() req: { user: JwtPayload },
    @Body() body: { newPassword: string }
  ) {
    await this.auth.updatePassword(+req.user.sub, body.newPassword);
  }

  @Post('token/access/refresh')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthRefreshGuard)
  @ApiResponse({
    description: 'Refreshes access token.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Access token has been successfully refreshed.')
  async refreshAccessToken(
    @Req() req: { user: JwtPayload },
    @Res({ passthrough: true }) res: Response
  ) {
    const jwtAccessToken = await this.auth.exchangeAccessToken(req.user);
    const isProdEnv = ['prod', 'production'].includes(
      this.configService.get<string>('NODE_ENV', '')
    );

    res.cookie('access_token', jwtAccessToken, {
      httpOnly: isProdEnv,
      maxAge: 1000 * +this.configService.get('JWT_ACCESS_TOKEN_EXPIRES'),
      sameSite: 'none',
      secure: isProdEnv
    });
  }

  @Delete('token/refresh/revoke')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthRefreshGuard)
  @ApiResponse({ description: 'Revokes refresh token.', status: HttpStatus.OK })
  @SuccessResponse('Refresh token has been successfully revoked.')
  async revokeRefreshTokens(@Req() req: { user: JwtPayload }) {
    await this.auth.revokeRefreshToken(req.user);
  }
}
