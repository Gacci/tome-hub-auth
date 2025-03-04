import { Module } from '@nestjs/common';

import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SequelizeModule } from '@nestjs/sequelize';

import { AuthService } from './auth.service';
import { RedisService } from '../redis/redis.service';
import { SessionTokenService } from '../user-session/session-token.service';

import { JwtStrategy } from './strategies/jwt.strategy';

import { AuthController } from './auth.controller';

import { MailerModule } from '../mailer/mailer.module';

import { User } from '../user/user.entity';
import { SessionToken } from '../user-session/session-token.entity';

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
    PassportModule.register({ defaultStrategy: 'jwt' }),
    SequelizeModule.forFeature([User, SessionToken])
  ],
  providers: [AuthService, JwtStrategy, RedisService, SessionTokenService],
  exports: [AuthService, JwtStrategy, PassportModule, RedisService, JwtModule]
})
export class AuthModule {}
