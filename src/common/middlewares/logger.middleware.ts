import { NextFunction } from 'express';

export function LoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  {
    console.log('request...', req.method, 'url', req.url);
    next();
  }
}
