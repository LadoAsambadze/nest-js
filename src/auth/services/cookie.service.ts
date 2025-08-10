import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';

@Injectable()
export class CookieService {
    constructor(private config: ConfigService) {}

    setAuthTokensCookies(response: Response, refreshToken: string): void {
        const isProduction = this.config.get<string>('NODE_ENV') === 'production';

        const refreshTokenOptions = {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? ('none' as const) : ('lax' as const),
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/',
        };

        response.cookie('refreshToken', refreshToken, refreshTokenOptions);
    }

    setRefreshTokenCookie(response: Response, refreshToken: string): void {
        const isProduction = this.config.get<string>('NODE_ENV') === 'production';

        const cookieOptions = {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? ('none' as const) : ('lax' as const),
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/',
        };

        response.cookie('refreshToken', refreshToken, cookieOptions);
    }

    clearAuthCookies(response: Response): void {
        const isProduction = this.config.get<string>('NODE_ENV') === 'production';

        const cookieOptions = {
            path: '/',
            secure: isProduction,
            sameSite: isProduction ? ('none' as const) : ('lax' as const),
        };

        response.clearCookie('refreshToken', { ...cookieOptions, httpOnly: true });
    }

    clearRefreshTokenCookie(response: Response): void {
        const isProduction = this.config.get<string>('NODE_ENV') === 'production';

        const cookieOptions = {
            path: '/',
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? ('none' as const) : ('lax' as const),
        };

        response.clearCookie('refreshToken', cookieOptions);
    }
}
