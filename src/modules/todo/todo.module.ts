import { Module } from '@nestjs/common';
import { TodoController } from './todo.controller';
import { TodoService } from './todo.service';
import { RedisModule } from 'src/redis/redis.module';
import { AuthGuard } from 'src/common/guard/auth.guard';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Todo } from 'src/modules/todo/entity/todo.entity';
import { User } from 'src/modules/auth/entity/user.entity';
import { JwtModuleConfig } from 'src/config/jwt-config.module';
import { JwtService } from '@nestjs/jwt';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { TodoGateWay } from './todo.gateway';
import { BullModule } from '@nestjs/bullmq';
import { BullMQAction } from 'src/common/constant/bullmq.constant';
import { TodoServiceQueue } from './bullmq/todo/todo-service.queue';
import { TodoQueue } from './bullmq/todo/todo.queue';
import { TodoQueueProcessor } from './bullmq/todo/processor-todos.queue';
import { BullModuleConfig } from 'src/config/bull.config.module';

@Module({
  imports: [
    RedisModule,
    JwtModuleConfig,
    TypeOrmModule.forFeature([Todo, User]),
    EventEmitterModule.forRoot(),
    BullModuleConfig,
    BullModule.registerQueue({ name: BullMQAction.TodoQueue }),
  ],
  controllers: [TodoController],
  providers: [
    TodoService,
    AuthGuard,
    JwtService,
    TodoGateWay,
    TodoServiceQueue,
    TodoQueue,
    TodoQueueProcessor,
  ],
  exports: [TodoService, TodoGateWay, TodoQueue],
})
export class TodoModule {}
