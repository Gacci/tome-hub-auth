import { TokenType } from 'src/auth/models/session-token.model';

export interface JwtPayload {
  exp?: number;
  iat?: number;
  ref: string;
  sub: string;
  type?: TokenType;
}
