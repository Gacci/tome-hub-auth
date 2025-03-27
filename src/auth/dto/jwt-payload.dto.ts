import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';
import { TokenType } from '../models/session-token.model';

export class JwtPayloadDto implements JwtPayload {
  sub: string;
  exp: number;
  ref: string;
  type: TokenType;
}
