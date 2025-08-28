import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SequelizeModule } from '@nestjs/sequelize';

import { AuthController } from '@/auth/auth.controller';
import { AuthService } from '@/auth/auth.service';
import { SessionToken } from '@/auth/models/session-token.model';
import { AwsConfigService } from '@/aws/aws-config.service';
import { CollegesService } from '@/colleges/colleges.service';
import { College } from '@/colleges/models/college.model';
import { CheckUserAccessGuard } from '@/guards/user-access/check-user-access.guard';
import { MailerModule } from '@/mailer/mailer.module';
import { RabbitMQModule } from '@/rabbit-mq/rabbit-mq.module';
import { RedisModule } from '@/redis/redis.module';
import { User } from '@/user/user.model';

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
    CollegesService
  ]
})
export class AuthModule {}
