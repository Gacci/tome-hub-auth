import { Injectable } from '@nestjs/common';

import { EnvironmentService } from '@/common/services/environment/environment.service';

import { CookieOptions } from 'express';

@Injectable()
export class CookieService {
  constructor(private readonly env: EnvironmentService) {}

  getOptions(options: CookieOptions): CookieOptions {
    return {
      httpOnly: false, //this.env.isProduction(),
      secure: false,
      path: '/',
      ...(this.env.isProduction()
        ? {
            domain: 'sydebook.com',
            sameSite: 'lax' //'none' //change to 'none' when using https
          }
        : {
            sameSite: 'lax'
          }),
      ...options
    };
  }
}
