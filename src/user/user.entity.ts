import * as bcrypt from 'bcryptjs';
import dayjs from 'dayjs';
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
  Scopes,
  Table
} from 'sequelize-typescript';

@DefaultScope(() => ({
  attributes: { exclude: ['password'] }
}))
@Scopes(() => ({
  fullDataView: { attributes: { include: ['password'] } }
}))
@Table({ paranoid: true, tableName: 'Users', timestamps: true })
export class User extends Model<
  InferAttributes<User>,
  InferCreationAttributes<User>
> {
  @Column({ autoIncrement: true, primaryKey: true, type: DataType.BIGINT })
  declare userId: CreationOptional<number>;

  @Column({ allowNull: false, type: DataType.STRING(128), unique: true })
  declare email: string;

  @Column({ allowNull: false, type: DataType.STRING(512) })
  declare password: string;

  @Column({ allowNull: true, type: DataType.STRING(32) })
  declare firstName?: string | null;

  @Column({ allowNull: true, type: DataType.STRING(32) })
  declare lastName?: string | null;

  @Column({ allowNull: true, type: DataType.STRING(255) })
  declare profilePictureUrl?: string | null;

  @Column({ allowNull: false, defaultValue: false, type: DataType.BOOLEAN })
  declare is2faEnrolled?: boolean;

  @Column({ allowNull: true, type: DataType.STRING(16) })
  declare cellPhoneNumber?: string | null;

  @Column({ allowNull: true, type: DataType.STRING(64) })
  declare cellPhoneCarrier?: string | null;

  @Column({ defaultValue: false, type: DataType.BOOLEAN })
  declare isAccountVerified?: boolean;

  @Column({ allowNull: true, type: DataType.STRING(6) })
  declare verifyAccountOtp?: string | null;

  @Column({ allowNull: true, type: DataType.DATE })
  declare verifyAccountOtpIssuedAt?: Date | null;

  @Column({ allowNull: true, type: DataType.STRING(6) })
  declare loginOtp?: string | null;

  @Column({ allowNull: true, type: DataType.DATE })
  declare loginOtpIssuedAt?: Date | null;

  @Column({ allowNull: true, type: DataType.STRING(6) })
  declare resetPasswordOtp?: string | null;

  @Column({ allowNull: true, type: DataType.DATE })
  declare resetPasswordOtpIssuedAt?: Date | null;

  @Column({ type: DataType.DATE })
  declare deletedAt: Date | null; // Soft delete column

  @BeforeCreate
  @BeforeUpdate
  static async onUserChange(user: User) {
    const password = user.getDataValue('password');
    if (user.changed('password')) {
      user.setDataValue('password', await bcrypt.hash(password, 10));
    }

    if (user.getDataValue('loginOtp') && user.changed('loginOtp')) {
      user.setDataValue('loginOtpIssuedAt', dayjs().utc().toDate());
    }

    if (
      user.getDataValue('resetPasswordOtp') &&
      user.changed('resetPasswordOtp')
    ) {
      user.setDataValue('resetPasswordOtpIssuedAt', dayjs().utc().toDate());
    }

    if (
      user.getDataValue('verifyAccountOtp') &&
      user.changed('verifyAccountOtp')
    ) {
      user.setDataValue('verifyAccountOtpIssuedAt', dayjs().utc().toDate());
    }
  }

  async isSamePassword(password: string): Promise<boolean> {
    return bcrypt.compare(password, this.getDataValue('password'));
  }

  static async exists(where: Partial<InferAttributes<User>>) {
    return await User.findOne({ attributes: ['1'], raw: true, where });
  }
}
