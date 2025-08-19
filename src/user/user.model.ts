import * as bcrypt from 'bcryptjs';
import dayjs from 'dayjs';
import {
  CreationOptional,
  InferAttributes,
  InferCreationAttributes,
  Sequelize
} from 'sequelize';
import {
  BeforeCreate,
  BeforeUpdate,
  BelongsTo,
  Column,
  DataType,
  DefaultScope,
  ForeignKey,
  Model,
  PrimaryKey,
  Scopes,
  Table
} from 'sequelize-typescript';
import { Membership } from 'src/common/enums/membership.enum';

import { College } from '../colleges/models/college.model';

@DefaultScope(() => ({
  attributes: { exclude: ['password'] }
}))
@Scopes(() => ({
  fullDataView: { attributes: { include: ['password'] } }
}))
@Table({
  paranoid: true,
  tableName: 'Users',
  timestamps: true
})
export class User extends Model<
  InferAttributes<User>,
  InferCreationAttributes<User, { omit: 'college' | 'fullName' }>
> {
  @PrimaryKey
  @Column({ autoIncrement: true, type: DataType.BIGINT })
  declare userId: CreationOptional<number>;

  @ForeignKey(() => College)
  @Column({ allowNull: true, type: DataType.INTEGER })
  declare collegeId?: number;

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

  @Column({
    allowNull: true,
    defaultValue: Membership.FREE,
    type: DataType.ENUM(...Object.values(Membership))
  })
  declare membership?: Membership;

  @Column({
    allowNull: true,
    defaultValue: null,
    type: DataType.DATE
  })
  declare membershipExpiresAt?: Date;

  @Column({
    allowNull: false,
    defaultValue: false,
    get() {
      return Boolean(this.getDataValue('is2faEnabled'))
    },
    type: DataType.BOOLEAN
  })
  declare is2faEnabled?: boolean;

  @Column({ allowNull: true, type: DataType.STRING(16) })
  declare cellPhoneNumber?: string | null;

  @Column({ allowNull: true, type: DataType.STRING(64) })
  declare cellPhoneCarrier?: string | null;

  @Column({
    defaultValue: false,
    get () {
      return Boolean(this.getDataValue('isAccountVerified'))
    },
    type: DataType.BOOLEAN
  })
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

  @Column({ allowNull: true, type: DataType.STRING(6) })
  declare resetPasswordToken?: string | null;

  @Column({ allowNull: true, type: DataType.DATE })
  declare resetPasswordTokenIssuedAt?: Date | null;
  /*
  @Column({
    allowNull: true,
    defaultValue: () => Sequelize.literal('CURRENT_TIMESTAMP'),
    type: DataType.DATE
  })
  declare createdAt?: Date | null;

  @Column({
    allowNull: true,
    defaultValue: () => Sequelize.literal('CURRENT_TIMESTAMP'),
    type: DataType.DATE
  })
  declare updatedAt?: Date | null;

  @Column({
    allowNull: true,
    defaultValue: () => Sequelize.literal('CURRENT_TIMESTAMP'),
    type: DataType.DATE
  })
  declare deletedAt?: Date | null;
*/

  @Column({ type: DataType.VIRTUAL })
  get fullName() {
    return [
      ...(this.firstName ? [this.firstName] : []),
      ...(this.lastName ? [this.lastName] : [])
    ];
  }

  @BelongsTo(() => College)
  declare college?: College;

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
      user.getDataValue('resetPasswordToken') &&
      user.changed('resetPasswordToken')
    ) {
      user.setDataValue('resetPasswordTokenIssuedAt', dayjs().utc().toDate());
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
    return await User.findOne({
      attributes: [[Sequelize.literal('1'), 'existing']],
      raw: true,
      where
    });
  }

  static async findOneWithPassword(where: Partial<InferAttributes<User>>) {
    return await User.findOne({
      attributes: { include: ['password'] },
      where
    });
  }
}
