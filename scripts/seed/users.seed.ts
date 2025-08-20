import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { faker } from '@faker-js/faker';

import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import * as bcrypt from 'bcryptjs';
import { Op } from 'sequelize';
import { Sequelize } from 'sequelize-typescript';
import { College } from 'src/colleges/models/college.model';

import { AppModule } from '@/app.module';
import { Membership } from '@/common/enums/membership.enum';
import { User } from '@/user/user.model';

async function seedUserRatings(size: number = 100) {
  const app = await NestFactory.createApplicationContext(AppModule);
  const logger = new Logger('ratings.seed');

  dayjs.extend(utc);

  const sequelize = app.get(Sequelize);
  const CollegeModel = sequelize.model(College);
  const UserModel = sequelize.model(User);

  const colleges = await CollegeModel.findAll({
    attributes: ['collegeId', 'emailDomain'],
    raw: true,
    where: {
      emailDomain: { [Op.not]: null }
    }
  });

  const batchSize = 500;
  const totalInsertCount = Math.ceil(size / batchSize);

  for (let batch = 0; batch < totalInsertCount; batch++) {
    const users: Partial<User>[] = [];
    const start = batch * batchSize;
    const end = Math.min((batch + 1) * batchSize, size);

    for (let i = start; i < end; i++) {
      const college =
        colleges[Math.floor(faker.number.int({ min: 0, max: users.length }))];
      const firstName = faker.person.firstName();
      const lastName = faker.person.lastName();
      console.log(college);
      users.push({
        collegeId: college?.['collegeId'],
        email:
          `${firstName}.${lastName}@${college?.['emailDomain']}`.toLowerCase(),
        firstName,
        lastName,
        password: await bcrypt.hash('1234567890', 3),
        membership: faker.helpers.arrayElement(Object.values(Membership)),
        membershipExpiresAt: faker.number.int({ max: 1, min: 0 })
          ? faker.date.past()
          : faker.date.anytime(),
        profilePictureUrl: faker.image.personPortrait()
      });
    }

    try {
      await UserModel.bulkCreate(users);
      logger.log(`✅ Inserted batch ${batch + 1} of ${totalInsertCount}`);
    } catch (e) {
      logger.error(e);
    }
  }

  logger.log(`✅ Inserted a total of ${size} ratings`);

  await app.close();
  process.exit(0);
}

const size = process.env.SEED_SIZE ? parseInt(process.env.SEED_SIZE, 10) : 100;

// const noCollegeOnly =
//   process.env.NO_COLLEGE_ONLY &&
//   /^true|false$/.test(process.env.NO_COLLEGE_ONLY)
//     ? JSON.parse(process.env.NO_COLLEGE_ONLY)
//     : false;

//  SEED_SIZE=50000 NON_RATED_ONLY=false npm run seed:ratings
void seedUserRatings(size);
