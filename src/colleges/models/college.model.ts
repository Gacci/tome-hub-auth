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

import { User } from '@/user/user.model';

@Table({
  // paranoid: true,
  tableName: 'Colleges',
  timestamps: false
  // timestamps: true
})
export class College extends Model<
  InferAttributes<College>,
  InferCreationAttributes<College, { omit: 'user' }>
> {
  @PrimaryKey
  @Column({ allowNull: false, autoIncrement: true, type: DataType.INTEGER })
  declare collegeId?: CreationOptional<number>;

  @Column({ allowNull: true, type: DataType.STRING(255) })
  declare emailDomain?: string;

  // @Column({
  //   allowNull: true,
  //   defaultValue: () => Sequelize.literal('CURRENT_TIMESTAMP'),
  //   type: DataType.DATE(3)
  // })
  // declare createdAt?: Date;
  //
  // @Column({
  //   allowNull: true,
  //   defaultValue: () => Sequelize.literal('CURRENT_TIMESTAMP'),
  //   type: DataType.DATE(3)
  // })
  // declare updatedAt?: Date;
  //
  // @Column({ allowNull: true, type: DataType.DATE(3) })
  // declare deletedAt?: Date;

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
