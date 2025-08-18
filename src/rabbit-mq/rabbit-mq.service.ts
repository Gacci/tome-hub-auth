import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import * as amqp from 'amqplib';

export enum RoutingKey {
  TOKEN_ACCESS_REVOKE = 'token.access.revoke',
  TOKEN_REFRESH_REVOKE = 'token.refresh.revoke',
  USER_REGISTRATION = 'user.registration',
  USER_UPDATE = 'user.update'
}

@Injectable()
export class RabbitMQService implements OnModuleInit, OnModuleDestroy {
  private connection: amqp.ChannelModel;
  private channel: amqp.Channel;

  private readonly exchange: string = 'broadcast.auth';
  private readonly logger = new Logger(RabbitMQService.name);

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    try {
      //  'amqps://USERNAME:PASSWORD@your-broker-url.mq.us-east-1.amazonaws.com:5671'
      this.connection = await amqp.connect(
        this.configService.getOrThrow<string>('RABBITMQ_URL')
      );
      this.channel = await this.connection.createChannel();

      await this.channel.assertExchange(this.exchange, 'topic', {
        durable: false
      });

      this.logger.log('RabbitMQ connected.');
    } catch (error) {
      this.logger.error(error);
    }
  }

  async onModuleDestroy() {
    await this.channel.close();
    await this.connection.close();
  }

  publish<T = { [key: string]: any }>(routingKey: RoutingKey, message: T) {
    this.channel.publish(
      this.exchange,
      routingKey,
      Buffer.from(
        typeof message === 'string' ? message : JSON.stringify(message)
      )
    );
  }

  async subscribe(routingKey: RoutingKey, callback: (msg: string) => void) {
    const q = await this.channel.assertQueue('', { exclusive: true });
    await this.channel.bindQueue(q.queue, this.exchange, routingKey);
    await this.channel.consume(q.queue, msg => {
      if (msg) {
        const message = msg.content.toString();
        console.log(`📥 Received: ${message}`);
        callback(message);
        this.channel.ack(msg);
      }
    });
  }
}
