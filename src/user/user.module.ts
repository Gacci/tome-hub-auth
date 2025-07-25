import { Module } from '@nestjs/common';
import { SequelizeModule } from '@nestjs/sequelize';

import { UsersController } from './user.controller';
import { User } from './user.model';
import { UserService } from './user.service';

@Module({
  controllers: [UsersController],
  exports: [UserService, SequelizeModule], // Export SequelizeModule so it can be used in AuthModule
  imports: [SequelizeModule.forFeature([User])],
  providers: [UserService]
})
export class UserModule {}
