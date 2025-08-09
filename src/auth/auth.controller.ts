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

import { CookieOptions, Request, Response } from 'express';

// import { AwsConfigService, S3Bucket } from '../aws/aws-config.service';
import { SuccessResponse } from '../common/decorators/success-response.decorator';
import { ProfileImageUrlInterceptor } from '../common/interceptors/profile-image-url/profile-image-url.interceptor';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import {
  JWT_ACCESS_TOKEN_NAME,
  JWT_REFRESH_TOKEN_NAME
} from '../config/constants';
import { CheckUserAccessGuard } from '../guards/user-access/check-user-access.guard';
// import { userProfileStorage } from '../common/data/users-merchant-data';
import { AuthService } from './auth.service';
import { CredentialsDto } from './dto/credentials.dto';
import { EmailDto } from './dto/email.dto';
import { LoginAuthDto } from './dto/login.dto';
import { OtpDto } from './dto/otp.dto';
import { ProfilePictureUrlDto } from './dto/profile-picture-url.dto';
import { ProfileDto } from './dto/profile.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { VerifyAccountDto } from './dto/verify-account.dto';
import { AccountVerifiedGuard } from './guards/account-verified/account-verified.guard';
import { JwtAuthAccessGuard } from './guards/jwt-auth-access/jwt-auth-access.guard';
import { JwtAuthRefreshGuard } from './guards/jwt-auth-refresh/jwt-auth-refresh.guard';

@ApiTags('Auth')
@Controller()
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    // private readonly awsConfigService: AwsConfigService,
    private readonly config: ConfigService
  ) {}

  @Post('account/register')
  @ApiResponse({
    description: 'Registers a new users',
    status: HttpStatus.CREATED
  })
  @SuccessResponse('You account has successfully been created')
  async create(@Body() createAuthDto: RegisterAuthDto) {
    await this.auth.register(createAuthDto.email, createAuthDto.password);
  }

  @HttpCode(HttpStatus.OK)
  @Post('account/register/otp/resend')
  @UseGuards(JwtAuthAccessGuard, AccountVerifiedGuard)
  @ApiResponse({
    description: 'Emails an OTP for users to confirm registration.',
    status: HttpStatus.OK
  })
  @SuccessResponse(
    'You will shortly receive an OTP if we are able to match you in our records'
  )
  async sendRegisterOtp(
    @Req() req: { user: JwtPayload },
    @Body() body: EmailDto
  ) {
    await this.auth.sendRegisterOtp(body.email);
  }

  @HttpCode(HttpStatus.OK)
  @Post('account/verify')
  @UseGuards(JwtAuthAccessGuard, AccountVerifiedGuard)
  @ApiResponse({
    description: 'Verifies OTP for users to confirm registration.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You account has been successfully verified')
  async verifyAccount(
    @Req() req: { user: JwtPayload },
    @Body() body: VerifyAccountDto
  ) {
    await this.auth.verifyAccount(body);
  }

  @Post('account/login')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    description:
      'Grants access to users (requires OTP if users is enrolled in 2FA authentication).',
    status: HttpStatus.OK
  })
  @SuccessResponse('You have successfully logged in')
  async login(
    @Res({ passthrough: true }) res: Response,
    @Body() loginAuthDto: LoginAuthDto
  ) {
    const tokens = await this.auth.login(loginAuthDto);
    const isProdEnv = ['prod', 'production'].includes(
      this.config.get<string>('NODE_ENV', '')
    );

    const options: CookieOptions = {
      httpOnly: false, // Prevent JS access
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/',
      sameSite: isProdEnv ? 'none' : 'lax', // Allow cross-origin in prod
      secure: isProdEnv // Use HTTPS in prod only
    };

    res.cookie(JWT_ACCESS_TOKEN_NAME, tokens?.jwtAccessToken, {
      ...options,
      maxAge: 1000 * +this.config.get('JWT_ACCESS_TOKEN_EXPIRES')
    });
    res.cookie(JWT_REFRESH_TOKEN_NAME, tokens?.jwtRefreshToken, {
      ...options,
      maxAge: 1000 * +this.config.get('JWT_REFRESH_TOKEN_EXPIRES')
    });

    return {
      [JWT_ACCESS_TOKEN_NAME]: tokens?.jwtAccessToken,
      [JWT_REFRESH_TOKEN_NAME]: tokens?.jwtRefreshToken
    };
  }

  @Delete('account/logout')
  @UseGuards(JwtAuthRefreshGuard)
  @ApiResponse({
    description: 'Logs out authenticated users.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You have successfully logged out')
  async logout(
    @Req() req: { user: JwtPayload },
    @Res({ passthrough: true }) res: Response
  ) {
    console.log(
      '**************************  LOG OUT ************************** '
    );
    const isProdEnv = ['prod', 'production'].includes(
      this.config.get<string>('NODE_ENV', '')
    );
    await this.auth.revokeRefreshToken(req.user);

    const options: CookieOptions = {
      httpOnly: isProdEnv, //isProdEnv,
      maxAge: 1000 * +this.config.get('JWT_ACCESS_TOKEN_EXPIRES'),
      domain: 'localhost', // Same domain as when setting the cookie
      path: '/',
      sameSite: isProdEnv ? 'none' : 'lax', // Allow cross-origin in prod
      secure: isProdEnv // Use HTTPS in prod only
    };

    // Clear both access and refresh token cookies
    res.clearCookie(JWT_ACCESS_TOKEN_NAME, options);
    res.clearCookie(JWT_REFRESH_TOKEN_NAME, options);
  }

  @Post('account/login/otp/resend')
  @ApiResponse({ description: 'Sends login OTP.', status: HttpStatus.OK })
  @SuccessResponse('We have initiated a message to send an OTP to your email')
  async resendLoginOtp(@Body() body: CredentialsDto) {
    return this.auth.sendLoginOtp(body);
  }

  @Get('account')
  @UseInterceptors(ProfileImageUrlInterceptor)
  @UseGuards(JwtAuthAccessGuard)
  @ApiResponse({
    description: "Reads authenticated users's merchant.",
    status: HttpStatus.OK
  })
  async findOne(@Req() req: { user: JwtPayload }) {
    return ProfileDto.from(await this.auth.findProfile(+req.user.sub));
  }

  @Patch('account/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  @ApiResponse({
    description: 'Updates authenticated users.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Your account has been successfully updated')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Req() req: { user: JwtPayload },
    @Body() body: UpdateAuthDto
  ) {
    await this.auth.update(id, body);
  }

  @Delete('account/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  @ApiResponse({
    description: 'Deletes account for authenticated users.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Your account has been successfully deleted')
  async remove(@Req() req: { user: JwtPayload }) {
    await this.auth.remove(+req.user.sub);
  }

  @Post('account/image')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard)
  @ApiResponse({
    description: 'Updates image for authenticated users.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Your image has been successfully uploaded')
  @UseInterceptors(FileInterceptor('file')) // { data: userProfileStorage }
  async setProfilePicture(
    @Req() req: { user: JwtPayload },
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 1024 * 1024 * 2 }),
          new FileTypeValidator({ fileType: 'image/*' })
        ]
      })
    )
    uploaded: Express.Multer.File
  ) {
    return ProfilePictureUrlDto.from(
      await this.auth.updateProfilePicture(+req.user.sub, uploaded)
    );
    // const response = await this.awsConfigService.upload(
    //   S3Bucket.PROFILES,
    //   uploaded
    // );
    //
    // new ProfilePictureUrlDto(
    //   await this.auth.update(+req.users.sub, {
    //     // profilePictureUrl: uploaded.filename
    //     profilePictureUrl: response.filename
    //   })
    // );
  }

  @Post('password/reset/otp/send')
  @ApiResponse({
    description: 'Sends password reset OTP.',
    status: HttpStatus.OK
  })
  @SuccessResponse('We have initiated a message to send an OTP to your email')
  async sendPasswordOtp(@Body() body: EmailDto) {
    await this.auth.sendResetPasswordOtp(body.email);
  }

  @Post('password/reset/otp/verify')
  @ApiResponse({
    description: 'Verifies OTP issues for password reset.',
    status: HttpStatus.OK
  })
  async verifyResetPasswordOtp(@Body() body: EmailDto & OtpDto) {
    return await this.auth.verifyResetPasswordOtp(body.email, body.otp);
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    description: 'Resets password for users providing OTP.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You password has been successfully reset')
  async resetPassword(@Body() body: ResetPasswordDto) {
    await this.auth.resetPassword(body);
  }

  @Post('password/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard, CheckUserAccessGuard)
  @ApiResponse({
    description: 'Changes password for users specified by `id`.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You password has been successfully changed')
  async updatePassword(
    @Req() req: { user: JwtPayload },
    @Body() body: { newPassword: string }
  ) {
    await this.auth.updatePassword(+req.user.sub, body.newPassword);
  }

  @Get('token')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthAccessGuard)
  getAccessToken(@Req() req: Request) {
    return {
      [JWT_ACCESS_TOKEN_NAME]: req.cookies[JWT_ACCESS_TOKEN_NAME] as string
    };
  }

  @Post('token/access/refresh')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthRefreshGuard)
  @ApiResponse({
    description: 'Refreshes access token.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Access token has been successfully refreshed')
  async refreshAccessToken(
    @Req() req: { user: JwtPayload },
    @Res({ passthrough: true }) res: Response
  ) {
    const jwtAccessToken = await this.auth.exchangeAccessToken(req.user);
    console.log('jwtAccessToken: ', jwtAccessToken, 'req.user: ', req.user);
    const isProdEnv = ['prod', 'production'].includes(
      this.config.get<string>('NODE_ENV', '')
    );

    res.cookie(JWT_ACCESS_TOKEN_NAME, jwtAccessToken, {
      httpOnly: isProdEnv, //isProdEnv,
      maxAge: 1000 * +this.config.get('JWT_ACCESS_TOKEN_EXPIRES'),
      path: '/',
      sameSite: isProdEnv ? 'none' : 'lax', // Allow cross-origin in prod
      secure: isProdEnv // Use HTTPS in prod only
    });

    return { [JWT_ACCESS_TOKEN_NAME]: jwtAccessToken };
  }

  @Delete('token/refresh/revoke')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthRefreshGuard)
  @ApiResponse({ description: 'Revokes refresh token.', status: HttpStatus.OK })
  @SuccessResponse('Refresh token has been successfully revoked')
  async revokeRefreshTokens(@Req() req: { user: JwtPayload }) {
    await this.auth.revokeRefreshToken(req.user);
  }
}
