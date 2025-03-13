import {
  CanActivate,
  ExecutionContext,
  Injectable,
  InternalServerErrorException,
  PreconditionFailedException,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { Request } from 'express';
import { Observable } from 'rxjs';

import {
  CHECK_USER_ACCESS_OPTIONS,
  CheckUserAccessGuardOptions
} from '../../common/decorators/check-user-access.decorator';
import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';

@Injectable()
export class CheckUserAccessGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(
    context: ExecutionContext
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>();

    const args = this.reflector.get<CheckUserAccessGuardOptions>(
      CHECK_USER_ACCESS_OPTIONS,
      context.getHandler()
    );

    const opts: CheckUserAccessGuardOptions = {
      idPropertyName: 'sub',
      routeParamName: 'id',
      ...(args ? args : {})
    };

    if (!opts.idPropertyName) {
      throw new InternalServerErrorException(
        `'idPropertyName' cannot be null.`
      );
    }

    if (!opts.routeParamName) {
      throw new InternalServerErrorException(
        `'routeParamName' cannot be null.`
      );
    }

    const idPropertyName = opts.idPropertyName
      ? request.user[opts.idPropertyName]
      : null;
    const routeParamName = opts.routeParamName
      ? request.params[opts.routeParamName]
      : null;

    if (!idPropertyName) {
      throw new PreconditionFailedException(
        `JWT property '${opts.idPropertyName}' not found.`
      );
    }

    if (!routeParamName) {
      throw new PreconditionFailedException(
        `Param '${opts.routeParamName}' not found.`
      );
    }

    if (idPropertyName !== routeParamName) {
      throw new UnauthorizedException('Not allowed.');
    }

    return true;
  }
}
