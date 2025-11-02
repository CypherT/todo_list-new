import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { RedisConfig } from 'src/common/interfaces/redis-config.interface';

@Module({
  imports: [
    BullModule.forRootAsync({
      inject: ['REDIS_BULLMQ'],
      useFactory: (redisConfig: RedisConfig) => ({
        connection: redisConfig,
      }),
    }),
  ],
  exports: [BullModule],
})
export class BullModuleConfig {}
