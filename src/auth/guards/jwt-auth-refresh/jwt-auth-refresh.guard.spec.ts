import { JwtAuthRefreshGuard } from './jwt-auth-refresh.guard';

describe('JwtAuthRefreshGuard', () => {
  it('should be defined', () => {
    expect(new JwtAuthRefreshGuard()).toBeDefined();
  });
});
