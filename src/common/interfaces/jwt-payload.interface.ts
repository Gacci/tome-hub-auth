import { TokenType } from 'src/auth/models/session-token.model';

export interface JwtPayload {
  exp?: number;
  iat?: number;
  ref: string;
  scope?: number;
  sub: number;
  type?: TokenType;
  verified?: boolean;
}
