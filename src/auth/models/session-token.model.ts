import {
  CreationOptional,
  InferAttributes,
  InferCreationAttributes
} from 'sequelize';
import {
  Column,
  DataType,
  ForeignKey,
  Model,
  PrimaryKey,
  Table
} from 'sequelize-typescript';

import { User } from '@/user/user.model';

export enum TokenStatus {
  ACTIVE = 'ACTIVE',
  EXCHANGED = 'EXCHANGED',
  EXPIRED = 'EXPIRED',
  REVOKED = 'REVOKED'
}

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH'
}

@Table({
  indexes: [{ fields: ['userId'], unique: false }],
  tableName: 'SessionTokens',
  timestamps: true
})
export class SessionToken extends Model<
  InferAttributes<SessionToken>,
  InferCreationAttributes<SessionToken>
> {
  @PrimaryKey
  @Column({
    allowNull: false,
    autoIncrement: true,
    type: DataType.BIGINT
  })
  declare sessionTokenId: CreationOptional<number>;

  @ForeignKey(() => User)
  @Column({ allowNull: false, type: DataType.INTEGER })
  declare userId: number;

  @Column({ allowNull: false, type: DataType.STRING(64) })
  declare familyId: string;

  @Column({ allowNull: false, type: DataType.STRING(1024) })
  declare token: string;

  @Column({
    allowNull: false,
    type: DataType.ENUM(...Object.values(TokenType))
  })
  declare type: TokenType;

  @Column({
    allowNull: false,
    type: DataType.ENUM(...Object.values(TokenStatus))
  })
  declare status: TokenStatus;
}
