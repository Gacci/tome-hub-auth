import { JwtAuthAccessGuard } from './jwt-auth-access.guard';

describe('JwtAuthAccessGuard', () => {
  it('should be defined', () => {
    expect(new JwtAuthAccessGuard()).toBeDefined();
  });
});
