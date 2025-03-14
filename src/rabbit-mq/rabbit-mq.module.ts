import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { RabbitMQService } from './rabbit-mq.service';

@Module({
  exports: [RabbitMQService],
  imports: [ConfigModule.forRoot()],
  providers: [RabbitMQService]
})
export class RabbitMQModule {}
