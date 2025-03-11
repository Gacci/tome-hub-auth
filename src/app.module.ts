import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { SequelizeModule } from '@nestjs/sequelize';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import { join } from 'path';

import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth/jwt-auth.guard';
import { BlacklistGuard } from './auth/guards/jwt-token-blacklist/jwt-token-blacklist.guard';
import { JwtStrategy } from './auth/strategies/jwt.strategy';
import { RedisModule } from './redis/redis.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot(),
    RedisModule,
    SequelizeModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        autoLoadModels: true,
        database: configService.get<string>('DB_NAME'),
        dialect: 'mysql',
        host: configService.get<string>('DB_HOST'),
        password: configService.get<string>('DB_PASS'),
        port: configService.get<number>('DB_PORT'),
        synchronize: true,
        timezone: configService.get<string>('DB_TZ'),
        username: configService.get<string>('DB_USER')
      })
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public')
    }),
    ThrottlerModule.forRoot([
      {
        limit: 60,
        name: 'short',
        ttl: 1000
      },
      {
        limit: 100,
        name: 'medium',
        ttl: 10000
      },
      {
        limit: 100,
        name: 'long',
        ttl: 60000
      }
    ]),
    UserModule
  ],
  providers: [
    JwtStrategy,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard
    },
    {
      provide: APP_GUARD,
      useClass: BlacklistGuard
    }
  ]
})
export class AppModule {}
