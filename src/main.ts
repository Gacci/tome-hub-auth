import {
  ClassSerializerInterceptor,
  Logger,
  ValidationPipe
} from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import cookieParser from 'cookie-parser';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { NextFunction } from 'express';
import * as fs from 'node:fs';

import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/success-response/success-response.interceptor';

async function bootstrap() {
  dayjs.extend(utc);
  const logger = new Logger('main.ts');
  console.log(process.env);
  const isProdEnv = process.env.NODE_ENV === 'prod';
  const app = await NestFactory.create(AppModule, {
    ...(isProdEnv
      ? {
          httpsOptions: {
            cert: fs.readFileSync('./localhost.pem'),
            key: fs.readFileSync('./localhost-key.pem')
          }
        }
      : {})
  });
  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('API for authentication')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

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
    origin: 'https://localhost:4200'
  });

  // Explicitly handle OPTIONS requests (preflight)
  app.use((req: Request, res: Response, next: NextFunction) => {
    console.log('----------------------------', req);
    next();
  });

  const port = process.env.AUTH_PORT ? +process.env.AUTH_PORT : 3000;
  try {
    await app.listen(port, '0.0.0.0');
    logger.log(
      `************** Server listening on port ${port} **************`
    );
  } catch (error) {
    logger.error(error);
  }
}
void bootstrap();
