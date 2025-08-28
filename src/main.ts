import {
  ClassSerializerInterceptor,
  Logger,
  ValidationPipe
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import cookieParser from 'cookie-parser';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import 'dotenv/config';
import * as fs from 'node:fs';

import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/success-response/success-response.interceptor';

async function bootstrap() {
  dayjs.extend(utc);
  const logger = new Logger('main.ts');

  const isProdEnv = process.env.APP_ENV === 'production';
  const isSslOn = process.env.USE_SSL === 'true';
  console.log(
    'auth should enable http-options: ',
    isSslOn,
    process.env.USE_SSL
  );
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    ...(isProdEnv || isSslOn
      ? {
          httpsOptions: {
            cert: fs.readFileSync('./localhost.pem'),
            key: fs.readFileSync('./localhost-key.pem')
          }
        }
      : {})
  });

  const configService = app.get(ConfigService);
  console.log(
    'ALLOWED ORIGINS: ',
    configService.get('ORIGIN_URL'),
    'USE_SSL: ',
    configService.get('USE_SSL')
  );

  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('API for authentication')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  app.setGlobalPrefix('v1/auth');
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      transformOptions: { enableImplicitConversion: true }
    })
  );
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
  app.useGlobalInterceptors(new ResponseInterceptor(new Reflector()));
  app.enableCors({
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    exposedHeaders: ['Set-Cookie'],
    maxAge: 86400,
    methods: ['DELETE', 'GET', 'OPTIONS', 'PATCH', 'POST', 'PUT'],
    origin:
        configService.get<string>('ORIGIN_URL', '')
            .split(',')
  });

  try {
    const port = configService.get<number>('AUTH_PORT', 3000);
    await app.listen(port); //'0.0.0.0'
    logger.log(
      `************** Server listening on port ${port} **************`
    );
  } catch (error) {
    logger.error(error);
  }
}
void bootstrap();
