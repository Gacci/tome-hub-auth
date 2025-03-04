import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '../mailer/mailer.module';
// import { UserModule } from '../user/user.module';
import { SequelizeModule } from '@nestjs/sequelize';
import { User } from '../user/user.entity';
import { SessionToken } from '../user-session/session-token.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SessionTokenService } from '../user-session/session-token.service'; // Import UserModule

@Module({
  controllers: [AuthController],
  imports: [
    ConfigModule.forRoot(),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1h' }
      })
    }),
    MailerModule,
    PassportModule.register({ defaultStrategy: 'jwt' }), // Needed for authentication
    SequelizeModule.forFeature([User, SessionToken])

  ], // Import UserModule and UserSessionModule
  providers: [AuthService, JwtStrategy, SessionTokenService],
  exports: [AuthService, JwtStrategy, PassportModule, JwtModule] //
})
export class AuthModule {}
