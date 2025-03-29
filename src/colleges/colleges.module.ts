import { Module } from '@nestjs/common';
import { SequelizeModule } from '@nestjs/sequelize';

import { CollegesController } from './colleges.controller';
import { CollegesService } from './colleges.service';
import { College } from './models/college.model';

@Module({
  controllers: [CollegesController],
  imports: [SequelizeModule.forFeature([College])],
  providers: [CollegesService]
})
export class CollegesModule {}
