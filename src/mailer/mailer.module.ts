import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerModule as NestMailerModule } from '@nestjs-modules/mailer';

import { MailerService } from './mailer.service';

@Module({
  imports: [
    ConfigModule.forRoot(),
    NestMailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return {
          transport: {
            host: configService.get<string>('MAIL_HOST', 'smtp.gmail.com'),
            port: configService.get<number>('MAIL_PORT', 587),
            secure: configService.get<boolean>('MAIL_SECURE', false),
            auth: {
              user: configService.get<string>('MAIL_USER'),
              pass: configService.get<string>('MAIL_PASS')
            },
            tls: {
              rejectUnauthorized: false, // Helps in some cases with SSL issues
              minVersion: 'TLSv1.2' // Forces TLS 1.2+
            }
          },
          defaults: {
            from: `"Support Team" <${configService.get<string>('MAIL_USER')}>`
          },
          logger: true,
          debug: true
        };
      }
    })
  ],
  providers: [MailerService],
  exports: [MailerService]
})
export class MailerModule {}
