import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';

import { Queue } from 'bullmq';
import { BullMQAction } from 'src/common/constant/bullmq.constant';
import { ListenTodoQueue } from 'src/common/constant/processor.constant';
import { CreateTodoDTO } from 'src/modules/todo/dto/create-todo.dto';

import { Todo } from 'src/modules/todo/entity/todo.entity';

@Injectable()
export class TodoQueue {
  constructor(@InjectQueue(BullMQAction.TodoQueue) private todoQueue: Queue) {}

  async createdTodoQueue(dto: CreateTodoDTO, userId: string) {
    const job = await this.todoQueue.add(
      ListenTodoQueue.CreateTodo,
      { dto, userId },
      {
        removeOnComplete: true,
        removeOnFail: true,
      },
    );
    return job;
  }

  async deleteTodoQueue(todos: Todo[], userId: string) {
    await this.todoQueue.add(ListenTodoQueue.DeleteTodo, {
      todos,
      userId,
    });
  }
}
