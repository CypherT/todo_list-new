import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { RedisModule } from 'src/redis/redis.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/modules/auth/entity/user.entity';
import { JwtModuleConfig } from 'src/config/jwt-config.module';
import { TodoModule } from 'src/modules/todo/todo.module';
import { BullModule } from '@nestjs/bullmq';
import { BullMQAction } from 'src/common/constant/bullmq.constant';
import { AuthQueue } from './bullmq/auth/auth.queue';
import { AuthQueueProcessor } from './bullmq/auth/processor-auth.queue';
import { SendMail } from './bullmq/auth/sendMail';
import { BullModuleConfig } from 'src/config/bull.config.module';

@Module({
  imports: [
    RedisModule,
    JwtModuleConfig,
    TypeOrmModule.forFeature([User]),
    TodoModule,
    BullModuleConfig,
    BullModule.registerQueue({ name: BullMQAction.AuthQueue }),
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthQueue, AuthQueueProcessor, SendMail],
  exports: [AuthQueue],
})
export class AuthModule {}
