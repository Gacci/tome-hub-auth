import { JwtPayload } from '@/common/interfaces/jwt-payload.interface';
import { CanActivate, ConflictException, ExecutionContext, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AccountVerifiedGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>();

    if (request.user.verified) {
      throw new ConflictException({
        error: 'UserVerified',
        message: 'Account had already been verified'
      });
    }

    return true;
  }
}
