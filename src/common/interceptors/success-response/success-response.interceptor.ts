import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { SUCCESS_RESPONSE } from '../../decorators/success-response.decorator';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const message = this.reflector.get<string>(
      SUCCESS_RESPONSE,
      context.getHandler()
    );
    console.log(message);
    return next
      .handle()
      .pipe(
        map((data: { [key: string]: any }) =>
          message ? { data, message } : data
        )
      );
  }
}
