import { Controller, Get } from '@nestjs/common';

import dayjs from 'dayjs';

import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  check() {
    return {
      status: 'ok',
      timestamp: dayjs().utc().toDate()
    };
  }
}
