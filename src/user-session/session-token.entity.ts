import {
  Table,
  Column,
  Model,
  ForeignKey,
  DataType,
  DefaultScope
} from 'sequelize-typescript';

import {
  CreationOptional,
  InferAttributes,
  InferCreationAttributes
} from 'sequelize';

import { User } from '../user/user.entity';

@DefaultScope(() => ({
  where: { deletedAt: null }
}))
@Table({ tableName: 'SessionTokens', timestamps: true, paranoid: true })
export class SessionToken extends Model<
  InferAttributes<SessionToken>,
  InferCreationAttributes<SessionToken>
> {
  @Column({ type: DataType.INTEGER, primaryKey: true, autoIncrement: true })
  declare sessionTokenId: CreationOptional<number>;

  @ForeignKey(() => User)
  @Column({ type: DataType.INTEGER, allowNull: false })
  declare userId: number;

  @Column({ allowNull: false })
  declare refreshToken: string;

  @Column({ type: DataType.DATE, allowNull: false })
  declare expiresAt: Date;

  @Column({ type: DataType.DATE })
  declare deletedAt: Date | null;
}
