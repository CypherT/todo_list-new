import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const { ip, url } = req;
    res.on('finish', () => {
      const { statusCode } = res;
      console.log(`${ip} request ${url} response status ${statusCode}`);
    });
    next();
  }
}
