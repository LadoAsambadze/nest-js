import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    app.use(cookieParser());

    // Enable CORS with credentials
    app.enableCors({
        origin: [
            'https://studio.apollographql.com',
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://localhost:5173',
            process.env.FRONTEND_URL || 'http://localhost:3000',
        ],
        credentials: true, // ❗ ESSENTIAL for cookies
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
        allowedHeaders: [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Cookie', // ✅ Add Cookie header
            'Set-Cookie', // ✅ Add Set-Cookie header
            'apollo-require-preflight',
        ],
        exposedHeaders: ['Set-Cookie'],
        optionsSuccessStatus: 200, // Some legacy browsers choke on 204
    });

    console.log('🌐 CORS enabled with credentials');

    app.useGlobalPipes(new ValidationPipe());

    const port = configService.getOrThrow<number>('APPLICATION_PORT') || 3001;

    // ✅ Add middleware logging for debugging
    app.use((req, res, next) => {
        if (req.url.includes('graphql') && req.method === 'POST') {
            console.log(`📡 ${req.method} ${req.url}`);
            console.log('🍪 Cookies received:', req.headers.cookie || 'None');
            console.log('🌍 Origin:', req.headers.origin || 'None');
        }
        next();
    });

    await app.listen(port);

    console.log(`🚀 Server ready at: http://localhost:${port}/graphql`);
    console.log('🔧 Cookie parser and CORS configured for authentication');
}
bootstrap();
