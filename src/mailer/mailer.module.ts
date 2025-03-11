import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { MailerModule as NestMailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';

import { join } from 'path';

import { MailerService } from './mailer.service';

@Module({
  exports: [MailerService],
  imports: [
    ConfigModule.forRoot(),
    NestMailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return {
          debug: true,
          defaults: {
            from: `"Support Team" <${configService.get<string>('MAIL_USER')}>`
          },
          logger: true,
          template: {
            adapter: new EjsAdapter(),
            dir: join(__dirname, 'templates'),
            options: {
              strict: false
            }
          },
          transport: {
            auth: {
              pass: configService.get<string>('MAIL_PASS'),
              user: configService.get<string>('MAIL_USER')
            },
            host: configService.get<string>('MAIL_HOST', 'smtp.gmail.com'),
            port: configService.get<number>('MAIL_PORT', 587),
            secure: configService.get<boolean>('MAIL_SECURE', false),
            tls: {
              minVersion: 'TLSv1.2', // Forces TLS 1.2+
              rejectUnauthorized: false // Helps in some cases with SSL issues
            }
          }
        };
      }
    })
  ],
  providers: [MailerService]
})
export class MailerModule {}
