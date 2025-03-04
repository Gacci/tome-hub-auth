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

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH'
}

@DefaultScope(() => ({
  where: { deletedAt: null }
}))
@Table({ tableName: 'session_tokens', timestamps: true, paranoid: true })
export class SessionToken extends Model<
  InferAttributes<SessionToken>,
  InferCreationAttributes<SessionToken>
> {
  @Column({ type: DataType.INTEGER, primaryKey: true, autoIncrement: true })
  declare sessionTokenId: CreationOptional<number>;

  @ForeignKey(() => User)
  @Column({ type: DataType.INTEGER, allowNull: false })
  declare userId: number; // ✅ Use `declare` to avoid shadowing Sequelize attributes

  @Column({
    type: DataType.ENUM(...Object.values(TokenType)), // ✅ Use spread operator to define ENUM correctly
    allowNull: false
  })
  declare typeOfToken: TokenType; // ✅ Use `declare`

  @Column({ allowNull: false })
  declare refreshToken: string; // ✅ Use `declare`

  @Column({ type: DataType.DATE, allowNull: false })
  declare expiresAt: Date; // ✅ Use `declare`

  @Column({ type: DataType.DATE })
  declare deletedAt: Date | null; // ✅ Use `declare` for soft delete
}
