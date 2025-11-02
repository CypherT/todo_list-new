import { Processor, WorkerHost } from '@nestjs/bullmq';

import { TodoServiceQueue } from './todo-service.queue';
import { Job } from 'bullmq';

import {
  QueueTodoInterface,
  QueueTodoInterfaceDel,
} from '../../interface/queue.todo.interface';
import { ListenTodoQueue } from 'src/common/constant/processor.constant';
import { BullMQAction } from 'src/common/constant/bullmq.constant';

@Processor(BullMQAction.TodoQueue)
export class TodoQueueProcessor extends WorkerHost {
  constructor(private readonly todoQueueService: TodoServiceQueue) {
    super();
  }

  async process(job: Job): Promise<any> {
    switch (job.name) {
      case ListenTodoQueue.CreateTodo:
        return await this.createTodoProcessor(job);
      case ListenTodoQueue.DeleteTodo:
        return this.deleteTodosProcessor(job);
      default:
        break;
    }
  }
  async createTodoProcessor(job: Job) {
    const { dto, userId } = job.data as QueueTodoInterface;
    return await this.todoQueueService.createTodoService(dto, userId);
  }

  deleteTodosProcessor(job: Job) {
    const { todos } = job.data as QueueTodoInterfaceDel;
    return this.todoQueueService.deleteAllTodoService(todos);
  }
}
