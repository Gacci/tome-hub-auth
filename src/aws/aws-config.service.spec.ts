import { Test, TestingModule } from '@nestjs/testing';

import { AwsConfigService } from '@/aws/aws-config.service';

describe('AwsConfigService', () => {
  let service: AwsConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AwsConfigService]
    }).compile();

    service = module.get<AwsConfigService>(AwsConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
