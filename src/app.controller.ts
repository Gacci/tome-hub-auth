import { Controller, Get } from '@nestjs/common';

import { AppService } from './app.service';
import dayjs from 'dayjs';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  check() {
    return {
      status: 'ok',
      timestamp: dayjs().utc().toDate(),
    };
  }
}
