import {
  ClassSerializerInterceptor,
  Logger,
  ValidationPipe
} from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import cookieParser from 'cookie-parser';
import dayjs from 'dayjs';
import duration from 'dayjs/plugin/duration';
// import timezone from 'dayjs/plugin/timezone';
import utc from 'dayjs/plugin/utc';

import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/success-response/success-response.interceptor';

async function bootstrap() {
  // Use the plugin
  // dayjs.extend(timezone);
  dayjs.extend(duration);
  dayjs.extend(utc);

  const logger = new Logger('main.ts');

  const app = await NestFactory.create(AppModule);
  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('API for authentication')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
  app.useGlobalInterceptors(new ResponseInterceptor(new Reflector()));
  app.enableCors({
    credentials: true,
    origin: ['http://127.0.0.1:3000', 'http://localhost:3000']
  });

  const port = process.env.PORT ? +process.env.PORT : 3001;
  await app.listen(port);

  logger.log(`*********** Server listening on port ********** ${port}`);
}
void bootstrap().then(r => console.log(r));
