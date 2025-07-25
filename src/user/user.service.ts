import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';

import { Op } from 'sequelize';

import { SearchUsersDto } from './dto/search-user.dto';
import { User } from './user.model';

@Injectable()
export class UserService {
  constructor(@InjectModel(User) private readonly users: typeof User) {}

  findOne(userId: number) {
    return this.users.findByPk(userId);
  }

  async search(query: SearchUsersDto) {
    return await this.users.findAll({
      attributes: [
        'userId',
        'email',
        'membership',
        'membershipExpiresAt',
        'isAccountVerified'
      ],
      limit: query.pageSize,
      offset: query.pageSize * (query.pageNumber - 1),
      // raw: true,
      where: {
        ...(query.userId?.length ? { userId: { [Op.in]: query.userId } } : {}),
        ...(query.collegeId ? { collegeId: query.collegeId } : {}),
        ...(query.email?.length ? { email: { [Op.in]: query.email } } : {})
      }
    });
  }
}
