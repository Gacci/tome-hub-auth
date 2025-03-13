import { SetMetadata } from '@nestjs/common';

export const SUCCESS_RESPONSE = 'success-response';

export const SuccessResponse = (message: string) =>
  SetMetadata(SUCCESS_RESPONSE, message);
