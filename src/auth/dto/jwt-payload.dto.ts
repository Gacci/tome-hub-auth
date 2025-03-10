import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';
import { TokenType } from '../entities/session-token.entity';

export class JwtPayloadDto implements JwtPayload {
  sub: string;
  exp: number;
  ref: string;
  type: TokenType;
}
