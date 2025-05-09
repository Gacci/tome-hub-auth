import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SequelizeModule } from '@nestjs/sequelize';

import { AwsConfigService } from '../aws/aws-config.service';
import { CollegesService } from '../colleges/colleges.service';
import { College } from '../colleges/models/college.model';
import { CheckUserAccessGuard } from '../guards/user-access/check-user-access.guard';
import { MailerModule } from '../mailer/mailer.module';
import { RabbitMQModule } from '../rabbit-mq/rabbit-mq.module';
import { RedisModule } from '../redis/redis.module';
import { RedisService } from '../redis/redis.service';
import { User } from '../user/user.model';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SessionToken } from './models/session-token.model';

@Module({
  controllers: [AuthController],
  exports: [AuthService, JwtModule, PassportModule],
  imports: [
    ConfigModule.forRoot(),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_TOKEN_SECRET'),
        signOptions: { expiresIn: '1h' }
      })
    }),
    MailerModule,
    PassportModule.register({}),
    RabbitMQModule,
    RedisModule,
    SequelizeModule.forFeature([College, SessionToken, User])
  ],
  providers: [
    AwsConfigService,
    AuthService,
    CheckUserAccessGuard,
    CollegesService,
    RedisService
  ]
})
export class AuthModule {}
