import * as bcrypt from 'bcryptjs';
import {
  CreationOptional,
  InferAttributes,
  InferCreationAttributes
} from 'sequelize';
import {
  BeforeCreate,
  BeforeUpdate,
  Column,
  DataType,
  DefaultScope,
  Model,
  Table
} from 'sequelize-typescript';

@DefaultScope(() => ({
  where: { deletedAt: null }
}))
@Table({ tableName: 'Users', timestamps: true, paranoid: true })
export class User extends Model<
  InferAttributes<User>,
  InferCreationAttributes<User>
> {
  @Column({ type: DataType.INTEGER, primaryKey: true, autoIncrement: true })
  declare userId: CreationOptional<number>; // id is optional during creation

  @Column({ type: DataType.STRING, unique: true, allowNull: false })
  declare email: string;

  @Column({ type: DataType.STRING, allowNull: false })
  declare password: string;

  @Column({ type: DataType.STRING, allowNull: true })
  declare firstName?: string | null;

  @Column({ type: DataType.STRING, allowNull: true })
  declare lastName?: string | null;

  @Column({ type: DataType.BOOLEAN, allowNull: true })
  declare is2faEnrolled?: boolean;

  @Column({ type: DataType.STRING, allowNull: true })
  declare cellPhoneNumber?: string | null;

  @Column({ type: DataType.STRING, allowNull: true })
  declare cellPhoneCarrier?: string | null;

  @Column({ type: DataType.STRING, allowNull: true })
  declare loginOtp?: string | null;

  @Column({ type: DataType.DATE, allowNull: true })
  declare loginOtpExpiresAt?: Date | null;

  @Column({ type: DataType.STRING, allowNull: true })
  declare resetPasswordOtp?: string | null;

  @Column({ type: DataType.DATE, allowNull: true })
  declare resetPasswordOtpExpiresAt?: Date | null;

  @Column({ type: DataType.DATE })
  declare deletedAt: Date | null; // Soft delete column

  @BeforeCreate
  @BeforeUpdate
  static async hashPassword(user: User) {
    const password = user.getDataValue('password');
    if (user.changed('password')) {
      user.setDataValue('password', await bcrypt.hash(password, 10));
    }
  }

  async isSamePassword(password: string): Promise<boolean> {
    console.log(
      password,
      await bcrypt.hash(password, 10),
      this.getDataValue('password'),
      await bcrypt.compare(password, this.getDataValue('password'))
    );
    return bcrypt.compare(password, this.getDataValue('password'));
  }
}
