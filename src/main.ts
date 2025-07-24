import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    // Enable CORS first
    app.enableCors({
        origin: [
            'https://studio.apollographql.com',
            'http://localhost:3000',
            'http://localhost:4000',
            'http://localhost:5173',
            process.env.FRONTEND_URL || 'http://localhost:3000',
        ],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'apollo-require-preflight', // Important for GraphQL
        ],
        exposedHeaders: ['Set-Cookie'],
    });

    app.use(cookieParser());
    app.useGlobalPipes(new ValidationPipe());

    const port = configService.getOrThrow<number>('APPLICATION_PORT') || 3001;
    await app.listen(port);

    console.log(`🚀 Server ready at: http://localhost:${port}/graphql`);
}
bootstrap();
