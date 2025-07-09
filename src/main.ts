import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    app.useGlobalPipes(new ValidationPipe());
    app.enableCors({
        origin: 'MY_FRONTEND',
        credentials: true,
    });

    await app.listen(
        configService.getOrThrow<number>('APPLICATION_PORT') || 3001
    );
}
bootstrap();
