import { InternalServerErrorException } from '@nestjs/common';
import { Request, Response } from 'express';

export function validateContext(context: any): { req: Request; res: Response } {
    const req = context.req as Request;
    const res = context.res as Response;

    if (!req) throw new InternalServerErrorException('Request object not found');
    if (!res) throw new InternalServerErrorException('Response object not found');

    return { req, res };
}