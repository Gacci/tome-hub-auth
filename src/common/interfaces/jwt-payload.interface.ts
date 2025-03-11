import { TokenType } from 'src/auth/entities/session-token.entity';

export interface JwtPayload {
  exp?: number;
  iat?: number;
  ref: string;
  sub: string;
  type?: TokenType;
}
