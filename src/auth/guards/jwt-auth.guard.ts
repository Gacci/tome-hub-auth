import { Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';

import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(
    context: ExecutionContext
  ): boolean | Promise<boolean> | Observable<boolean> {
    const handler = context.getHandler();
    const classRef = context.getClass();

    const isPublic =
      this.reflector.get<boolean>(IS_PUBLIC_KEY, handler) ||
      this.reflector.get<boolean>(IS_PUBLIC_KEY, classRef);

    console.log(`Handler: ${handler.name}, Class: ${classRef.name}, isPublic:`, isPublic);

    if (isPublic) {
      return true; // Allow public routes
    }

    return super.canActivate(context);
  }
}
