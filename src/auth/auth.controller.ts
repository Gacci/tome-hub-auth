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

import { AwsConfigService, S3Bucket } from '../aws/aws-config.service';
import { SuccessResponse } from '../common/decorators/success-response.decorator';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
// import { userProfileStorage } from '../common/storage/user-profile-storage';
import { AuthService } from './auth.service';
import { Public } from './decorators/public.decorator';
import { CredentialsDto } from './dto/credentials.dto';
import { EmailDto } from './dto/email.dto';
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
  constructor(
    private readonly auth: AuthService,
    private readonly awsConfigService: AwsConfigService
  ) {}

  @Public()
  @Post('account/register')
  @ApiResponse({
    description: 'Registers a new user',
    status: HttpStatus.CREATED
  })
  @SuccessResponse('Successfully created account.')
  async create(@Body() createAuthDto: RegisterAuthDto) {
    await this.auth.register(createAuthDto.email, createAuthDto.password);
  }

  @Public()
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

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('account/register/verify')
  @ApiResponse({
    description: 'Verifies OTP for user to confirm registration.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You account has been successfully verified.')
  async verifyAccount(@Body() body: VerifyAccountDto) {
    await this.auth.verifyAccount(body);
  }

  @Public()
  @Post('account/login')
  @ApiResponse({
    description:
      'Grants access to user (requires OTP if user is enrolled in 2FA authentication).',
    status: HttpStatus.OK
  })
  @SuccessResponse('Login successful.')
  async login(@Body() loginAuthDto: LoginAuthDto) {
    return await this.auth.login(loginAuthDto);
  }

  @Public()
  @Post('account/login/otp/resend')
  @ApiResponse({ description: 'Sends login OTP.', status: HttpStatus.OK })
  @SuccessResponse('Check your inbox for your OTP.')
  async resendLoginOtp(@Body() loginAuthDto: CredentialsDto) {
    return this.auth.sendLoginOtp(loginAuthDto);
  }

  @Get('account/:id')
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
  @ApiResponse({
    description: 'Updates profile image for authenticated user.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Successfully uploaded profile image.')
  @UseInterceptors(FileInterceptor('file')) // { storage: userProfileStorage }
  async setProfilePicture(
    @Request() req: { user: JwtPayload },
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

  @Public()
  @Post('password/reset/otp/send')
  @ApiResponse({
    description: 'Sends password reset OTP.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Check your inbox for your OTP.')
  async sendPasswordOtp(@Body() body: EmailDto) {
    await this.auth.sendPasswordResetOtp(body.email);
  }

  @Public()
  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
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
  @ApiResponse({
    description: 'Resets password for user specified by `id`.',
    status: HttpStatus.OK
  })
  @SuccessResponse('You password has been successfully changed.')
  async updatePassword(
    @Request() req: { user: JwtPayload },
    @Body() body: { newPassword: string }
  ) {
    await this.auth.updatePassword(+req.user.sub, body.newPassword);
  }

  @Post('token/access/refresh')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    description: 'Refreshes access token.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Refresh token has been successfully refreshed.')
  async refreshTokens(@Request() req: { user: JwtPayload }) {
    return await this.auth.exchangeAccessToken(req.user);
  }

  @Delete('token/refresh/revoke')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ description: 'Revokes refresh token.', status: HttpStatus.OK })
  @SuccessResponse('Refresh token has been successfully revoked.')
  async revokeTokens(@Request() req: { user: JwtPayload }) {
    await this.auth.revokeRefreshToken(req.user);
  }

  @Post('token/active')
  @ApiResponse({
    description: 'Verifies whether a token is an active token.',
    status: HttpStatus.OK
  })
  @SuccessResponse('Session status')
  async active(@Headers('authorization') headers: { authorization: string }) {
    return {
      active: !(await this.auth.isTokenBlacklisted(
        headers.authorization.replace(/^Bearer\s/, '')
      ))
    };
  }
}
