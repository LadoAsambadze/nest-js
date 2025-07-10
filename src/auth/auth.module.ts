import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
    imports: [
        PassportModule.register({ defaultStrategy: 'google' }),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: {
                    expiresIn:
                        configService.get<string>(
                            'JWT_ACCESS_TOKEN_EXPIRATION'
                        ) || '15m',
                },
            }),
            inject: [ConfigService],
        }),
    ],
    providers: [AuthService, AuthResolver, GoogleStrategy],
    exports: [AuthService],
})
export class AuthModule {}
