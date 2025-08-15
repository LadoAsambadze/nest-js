import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './services/auth.service';
import { AuthResolver } from './auth.resolver';
import { GoogleStrategy } from './strategies/google.strategy';
import { AuthController } from './controllers/auth.controller';
import { UserAccountService } from './services/user-account.service';
import { TokenService } from './services/token.service';
import { CookieService } from './services/cookie.service';
import { ScheduleModule } from '@nestjs/schedule';
import { ScheduledTasksService } from './services/sheduled-tasks.service';
import { EmailService } from './services/email.service';

@Module({
    imports: [
        ScheduleModule.forRoot(),
        PassportModule.register({ defaultStrategy: 'google' }),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: {
                    expiresIn: configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') || '1m',
                },
            }),
            inject: [ConfigService],
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthResolver,
        GoogleStrategy,
        AuthService,
        UserAccountService,
        TokenService,
        CookieService,
        ScheduledTasksService,
        EmailService,
    ],
    exports: [AuthService],
})
export class AuthModule {}
