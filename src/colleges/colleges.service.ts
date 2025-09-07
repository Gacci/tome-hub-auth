import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';

import { Op } from 'sequelize';

import { CreateCollegeDto } from './dto/create-college.dto';
import { UpdateCollegeDto } from './dto/update-college.dto';
import { College } from './models/college.model';

@Injectable()
export class CollegesService {
  constructor(
    @InjectModel(College) private readonly colleges: typeof College
  ) {}
  create(body: CreateCollegeDto) {
    return this.colleges.create(body);
  }

  findOne(collegeId: number) {
    return this.colleges.findByPk(collegeId);
  }

  update(collegeId: number, body: UpdateCollegeDto) {
    return this.colleges.update(body, { where: { collegeId } });
  }

  remove(collegeId: number) {
    return this.colleges.destroy({ where: { collegeId } });
  }

  findAllCampuses(email: string) {
    return this.colleges.findAll({
      where: {
        emailDomain: {
          [Op.or]: email
            .toLowerCase()
            .replace(/.+@/, '')
            .split('.')
            .map((_: string, i: number, tokens: string[]) =>
              tokens.slice(i).join('.')
            )
            .filter((domain: string) => domain.includes('.'))
        }
      }
    });
  }

  findOneCampus(email: string, collegeId?: number) {
    return this.colleges.findOne({
      where: {
        ...(collegeId ? { collegeId } : {}),
        emailDomain: {
          [Op.or]: email
            .toLowerCase()
            .replace(/.+@/, '')
            .split('.')
            .map((_: string, i: number, tokens: string[]) =>
              tokens.slice(i).join('.')
            )
            .filter((domain: string) => domain.includes('.'))
        }
      }
    });
  }
}
