import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    app.useGlobalPipes(new ValidationPipe());
    app.enableCors({
        origin: [
            'https://studio.apollographql.com',
            'http://localhost:3000', // Add your frontend URL if needed
            'http://localhost:4000', // Allow same origin
        ],
        credentials: true,
    });

    app.enableCors({
        credentials: true,
    });
    await app.listen(
        configService.getOrThrow<number>('APPLICATION_PORT') || 3001
    );
}
bootstrap();
