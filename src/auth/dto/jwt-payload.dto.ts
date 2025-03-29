import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';
import { TokenType } from '../models/session-token.model';

export class JwtPayloadDto implements JwtPayload {
  sub: number;
  exp: number;
  ref: string;
  scope: number;
  type: TokenType;
  verified?: boolean;
}
