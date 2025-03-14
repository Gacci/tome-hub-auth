import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { SequelizeModule } from '@nestjs/sequelize';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'node:path';
import { join } from 'path';

import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth/jwt-auth.guard';
import { BlacklistGuard } from './auth/guards/jwt-token-blacklist/jwt-token-blacklist.guard';
import { JwtStrategy } from './auth/strategies/jwt.strategy';
import { AwsModule } from './aws/aws.module';
// import { RabbitMQModule } from './rabbit-mq/rabbit-mq.module';
import { RedisModule } from './redis/redis.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot({
      envFilePath: [path.resolve(process.cwd(), '.env.development')],
      ignoreEnvFile: false,
      isGlobal: true,
      load: [
        () =>
          dotenv.parse(
            fs.readFileSync(
              process.env.NODE_ENV === 'development'
                ? '.env.development'
                : process.env.NODE_ENV === 'staging'
                  ? '.env.staging'
                  : '.env'
            )
          )
      ]
    }),
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
    UserModule,
    AwsModule
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
export class AppModule implements OnModuleInit {
  constructor(private configService: ConfigService) {}

  onModuleInit() {
    const nodeEnv = this.configService.get<string>('NODE_ENV');
    const dbHost = this.configService.get<string>('DB_HOST');

    console.log('--- Config Debugging ---');
    console.log('NODE_ENV:', process.env.NODE_ENV); // Direct log of NODE_ENV
    console.log('Environment variable NODE_ENV:', nodeEnv);
    console.log('DB_HOST:', dbHost);
  }
}
