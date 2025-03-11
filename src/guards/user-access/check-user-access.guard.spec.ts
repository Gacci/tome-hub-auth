import { Reflector } from '@nestjs/core';

import { CheckUserAccessGuard } from './check-user-access.guard';

describe('UserAccessGuard', () => {
  it('should be defined', () => {
    expect(new CheckUserAccessGuard(new Reflector())).toBeDefined();
  });
});
