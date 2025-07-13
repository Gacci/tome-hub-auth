import { TokenType } from 'src/auth/models/session-token.model';

import { Membership } from '../enums/membership.enum';

/**
 * mex      - Membership expiration
 * mbr      - Membership type
 * ref      - a reference to refresh token (for access tokens only)
 * scope    - scope where user can perform activity, i.e., search, see reviews
 * type     - token type
 * verified - whether user is verified
 */

export interface JwtPayload {
  exp?: number;
  iat?: number;
  ref: string;
  scope?: number;
  sub: number;
  mbr?: Membership;
  mex?: number;
  type?: TokenType;
  verified?: boolean;
}
