import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import dayjs from 'dayjs';
// import timezone from 'dayjs/plugin/timezone';
import utc from 'dayjs/plugin/utc';

import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/success-response/success-response.interceptor';

async function bootstrap() {
  // Use the plugin
  // dayjs.extend(timezone);
  dayjs.extend(utc);

  const app = await NestFactory.create(AppModule);
  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('API for authentication')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
  app.useGlobalInterceptors(new ResponseInterceptor(new Reflector()));
  app.enableCors({
    // origin: 'http://localhost',
    // credentials: true,
  });

  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap().then(r => console.log(r));
