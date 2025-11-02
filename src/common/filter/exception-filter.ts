import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(HttpException)
export class HandleException implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response: Response = ctx.getResponse();
    const status = exception.getStatus();

    const exceptionResponse = exception.getResponse();
    let message = 'Unknown error';
    let error = 'unknown';
    if (typeof exceptionResponse === 'string') {
      message = exceptionResponse;
    } else if (typeof exceptionResponse === 'object') {
      message = (exceptionResponse as any).message;
      error = (exceptionResponse as any).error;
    }
    response.status(status).json({
      ok: 0,
      t: status,
      d: message,
      e: error,
    });
  }
}
