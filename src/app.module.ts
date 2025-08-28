import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { SequelizeModule } from '@nestjs/sequelize';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import { LoggerModule } from 'nestjs-pino';
import { join } from 'path';

import { AuthModule } from './auth/auth.module';
import { JwtAccessStrategy } from './auth/strategies/jwt-access.strategy';
import { JwtRefreshStrategy } from './auth/strategies/jwt-refresh.strategy';
import { AwsModule } from './aws/aws.module';
import { CollegesModule } from './colleges/colleges.module';
import { RedisModule } from './redis/redis.module';
import { UserModule } from './user/user.module';
import { AppService } from '@/app.service';
import { AppController } from '@/app.controller';

@Module({
  // exports: ['JwtAccessStrategy', 'JwtRefreshStrategy'],
  controllers: [AppController],
  imports: [
    AuthModule,
    AwsModule,
    CollegesModule,
    ConfigModule.forRoot({
      // envFilePath: [path.resolve(process.cwd(), '.env')],
      ignoreEnvFile: true,
      isGlobal: true,
      load: [
        ...(process.env.APP_ENV === 'local'
          ? [() => dotenv.parse(fs.readFileSync('.env'))]
          : [])
      ]
    }),
    LoggerModule.forRoot({
      pinoHttp: {
        autoLogging: true, // logs each request automatically
        transport: {
          options: {
            colorize: true,
            ignore: 'pid,hostname',
            translateTime: 'SYS:standard'
          },
          target: 'pino-pretty' // Make logs readable in dev
        }
      }
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
    UserModule
  ],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: 'JwtAccessStrategy',
      useClass: JwtAccessStrategy
    },
    {
      provide: 'JwtRefreshStrategy',
      useClass: JwtRefreshStrategy
    }
  ]
})
export class AppModule implements OnModuleInit {
  constructor(private configService: ConfigService) {}

  onModuleInit() {
    // const nodeEnv = this.configService.get<string>('NODE_ENV');
    // const dbHost = this.configService.get<string>('DB_HOST');
    //
    // console.log('--- Config Debugging ---');
    // console.log(this.configService);
    // console.log('NODE_ENV:', process.env); // Direct log of NODE_ENV
    // console.log('Environment variable NODE_ENV:', nodeEnv);
    // console.log('DB_HOST:', dbHost);
  }
}