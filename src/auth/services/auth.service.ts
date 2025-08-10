import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Response, Request } from 'express';
import { SignupRequest } from '../dto/signup.dto';
import { SigninRequest } from '../dto/signin.dto';
import { GoogleUserData } from '../types/google-user.types';
import { AuthResponse } from '../types/auth-response.type';
import { CookieService } from './cookie.service';
import { UserAccountService } from './user-account.service';
import { TokenService } from './token.service';
import { RefreshTokenResponse } from '../types/refresh-token-response.type';

@Injectable()
export class AuthService {
    constructor(
        private userAccountService: UserAccountService,
        private tokenService: TokenService,
        private cookieService: CookieService
    ) {}

    async signup(dto: SignupRequest, response: Response): Promise<AuthResponse> {
        const user = await this.userAccountService.createUserWithCredentials(dto);

        const tokens = await this.tokenService.generateTokens(
            user.id,
            user.email,
            user.role,
            user.firstname,
            user.lastname
        );

        await this.tokenService.saveRefreshToken(user.id, tokens.refreshToken);
        this.cookieService.setAuthTokensCookies(response, tokens.accessToken);

        const { password, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async signupOrLoginWithGoogle(
        googleUser: GoogleUserData,
        response: Response
    ): Promise<AuthResponse> {
        const user = await this.userAccountService.signupOrLoginWithGoogle(googleUser);

        const tokens = await this.tokenService.generateTokens(
            user.id,
            user.email,
            user.role,
            user.firstname,
            user.lastname
        );

        await this.tokenService.saveRefreshToken(user.id, tokens.refreshToken);
        this.cookieService.setAuthTokensCookies(response, tokens.accessToken);

        const { password, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async signin(dto: SigninRequest, response: Response): Promise<AuthResponse> {
        const user = await this.userAccountService.validateCredentials(dto.email, dto.password);

        const tokens = await this.tokenService.generateTokens(
            user.id,
            user.email,
            user.role,
            user.firstname,
            user.lastname
        );

        await this.tokenService.saveRefreshToken(user.id, tokens.refreshToken);
        this.cookieService.setAuthTokensCookies(response, tokens.refreshToken);

        const { password, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async refreshAccessToken(request: Request, response: Response): Promise<RefreshTokenResponse> {
        const refreshToken = request.cookies['refreshToken'];

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not found');
        }

        const { payload, storedToken } = await this.tokenService.verifyRefreshToken(refreshToken);

        const isNearExpiry = await this.tokenService.isRefreshTokenNearExpiry(refreshToken, 1);

        if (isNearExpiry) {
            const newTokens = await this.tokenService.generateTokens(
                payload.sub,
                payload.email,
                payload.role,
                payload.firstname,
                payload.lastname,
                payload.avatar
            );

            await this.tokenService.revokeRefreshTokenById(storedToken.id);
            await this.tokenService.saveRefreshToken(payload.sub, newTokens.refreshToken);
            this.cookieService.setRefreshTokenCookie(response, newTokens.refreshToken);
            const user = await this.userAccountService.findById(payload.sub);

            return {
                accessToken: newTokens.accessToken,
                user: user,
            };
        } else {
            const newAccessToken = await this.tokenService.generateAccessToken(
                payload.sub,
                payload.email,
                payload.role,
                payload.firstname,
                payload.lastname,
                payload.avatar
            );

            const user = await this.userAccountService.findById(payload.sub);

            return {
                accessToken: newAccessToken,
                user: user,
            };
        }
    }

    async logout(request: Request, response: Response): Promise<{ message: string }> {
        const refreshToken = request.cookies['refreshToken'];

        if (refreshToken) {
            await this.tokenService.revokeRefreshToken(refreshToken);
        }

        this.cookieService.clearAuthCookies(response);

        return { message: 'Logged out successfully' };
    }

    async logoutAll(userId: string, response: Response): Promise<{ message: string }> {
        await this.tokenService.revokeAllUserTokens(userId);

        this.cookieService.clearAuthCookies(response);

        return { message: 'Logged out from all devices successfully' };
    }
}
