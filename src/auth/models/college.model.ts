import {
  CreationOptional,
  InferAttributes,
  InferCreationAttributes,
  Sequelize
} from 'sequelize';
import {
  Column,
  DataType,
  HasOne,
  Model,
  PrimaryKey,
  Table
} from 'sequelize-typescript';

import { User } from '../../user/user.entity';

@Table({
  paranoid: true,
  tableName: 'Colleges',
  timestamps: true
})
export class College extends Model<
  InferAttributes<College>,
  InferCreationAttributes<College>
> {
  @PrimaryKey
  @Column({ allowNull: false, autoIncrement: true, type: DataType.INTEGER })
  declare collegeId: CreationOptional<number>;

  @Column({ type: DataType.STRING(255) })
  declare emailDomain: string;

  // Define the reverse relationship (College has one User)
  @HasOne(() => User)
  declare user: User;

  static async exists(where: Partial<InferAttributes<College>>) {
    return await College.findOne({
      attributes: [[Sequelize.literal('1'), 'existing']],
      raw: true,
      where
    });
  }
}
