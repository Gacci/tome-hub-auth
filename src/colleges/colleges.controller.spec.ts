import { Test, TestingModule } from '@nestjs/testing';

import { CollegesController } from './colleges.controller';
import { CollegesService } from './colleges.service';

describe('CollegesController', () => {
  let controller: CollegesController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CollegesController],
      providers: [CollegesService]
    }).compile();

    controller = module.get<CollegesController>(CollegesController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
