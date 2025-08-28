"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const faker_1 = require("@faker-js/faker");
const dayjs_1 = __importDefault(require("dayjs"));
const utc_1 = __importDefault(require("dayjs/plugin/utc"));
const bcrypt = __importStar(require("bcryptjs"));
const sequelize_1 = require("sequelize");
const sequelize_typescript_1 = require("sequelize-typescript");
const college_model_1 = require("../../src/colleges/models/college.model");
const app_module_1 = require("../../src/app.module");
const membership_enum_1 = require("../../src/common/enums/membership.enum");
const user_model_1 = require("../../src/user/user.model");
async function seedUserRatings(size = 100) {
    const app = await core_1.NestFactory.createApplicationContext(app_module_1.AppModule);
    const logger = new common_1.Logger('ratings.seed');
    dayjs_1.default.extend(utc_1.default);
    const sequelize = app.get(sequelize_typescript_1.Sequelize);
    const CollegeModel = sequelize.model(college_model_1.College);
    const UserModel = sequelize.model(user_model_1.User);
    const colleges = await CollegeModel.findAll({
        attributes: ['collegeId', 'emailDomain'],
        raw: true,
        where: {
            emailDomain: { [sequelize_1.Op.not]: null }
        }
    });
    const batchSize = 500;
    const totalInsertCount = Math.ceil(size / batchSize);
    for (let batch = 0; batch < totalInsertCount; batch++) {
        const users = [];
        const start = batch * batchSize;
        const end = Math.min((batch + 1) * batchSize, size);
        for (let i = start; i < end; i++) {
            const college = colleges[Math.floor(faker_1.faker.number.int({ min: 0, max: users.length }))];
            const firstName = faker_1.faker.person.firstName();
            const lastName = faker_1.faker.person.lastName();
            console.log(college);
            users.push({
                collegeId: college?.['collegeId'],
                email: `${firstName}.${lastName}@${college?.['emailDomain']}`.toLowerCase(),
                firstName,
                lastName,
                password: await bcrypt.hash('1234567890', 3),
                membership: faker_1.faker.helpers.arrayElement(Object.values(membership_enum_1.Membership)),
                membershipExpiresAt: faker_1.faker.number.int({ max: 1, min: 0 })
                    ? faker_1.faker.date.past()
                    : faker_1.faker.date.anytime(),
                profilePictureUrl: faker_1.faker.image.personPortrait()
            });
        }
        try {
            await UserModel.bulkCreate(users);
            logger.log(`✅ Inserted batch ${batch + 1} of ${totalInsertCount}`);
        }
        catch (e) {
            logger.error(e);
        }
    }
    logger.log(`✅ Inserted a total of ${size} ratings`);
    await app.close();
    process.exit(0);
}
const size = process.env.SEED_SIZE ? parseInt(process.env.SEED_SIZE, 10) : 100;
void seedUserRatings(size);
//# sourceMappingURL=users.seed.js.map