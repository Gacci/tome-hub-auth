import { SetMetadata } from '@nestjs/common';

export type CheckUserAccessGuardOptions = {
  idPropertyName?: string;
  routeParamName?: string;
};

export const CHECK_USER_ACCESS_OPTIONS = 'check-users-access-options';

export const CheckUserAccess = (opts: CheckUserAccessGuardOptions) =>
  SetMetadata(CHECK_USER_ACCESS_OPTIONS, opts);
