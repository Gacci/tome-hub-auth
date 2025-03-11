import { JwtTokenBlacklistGuard } from './jwt-token-blacklist.guard';

describe('JwtTokenBlacklistGuard', () => {
  it('should be defined', () => {
    expect(new JwtTokenBlacklistGuard()).toBeDefined();
  });
});
