import { SetMetadata } from '@nestjs/common';

export const SUCCESS_RESPONSE = 'success-response';

export const SuccessResponse = (args: string) =>
  SetMetadata(SUCCESS_RESPONSE, args);
