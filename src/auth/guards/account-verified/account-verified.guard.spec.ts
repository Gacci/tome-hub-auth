import { AccountVerifiedGuard } from './account-verified.guard';

describe('AccountVerifiedGuard', () => {
  it('should be defined', () => {
    expect(new AccountVerifiedGuard()).toBeDefined();
  });
});
