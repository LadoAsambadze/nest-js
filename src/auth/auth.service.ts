import {
    ConflictException,
    Injectable,
    UnauthorizedException,
    BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';
import { PrismaService } from '../prisma/prisma.service';
import { hash, verify } from 'argon2';
import { AuthTokens } from './types/auth-tokens.type';
import { calculateExpiryDate } from '../common/utils/expiry-date.util';
import { AuthResponse } from './types/auth-response.type';
import { SignupRequest } from './dto/signup.dto';
import { GoogleUserData } from './types/google-user.types';
import { SigninRequest } from './dto/signin.dto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}

    async signup(
        dto: SignupRequest,
        response: Response
    ): Promise<AuthResponse> {
        const { firstname, lastname, email, avatar, password, phone } = dto;

        const existingUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            if (existingUser.method === 'GOOGLE') {
                throw new ConflictException(
                    'An account with this email already exists. Please sign in with Google instead.'
                );
            } else {
                throw new ConflictException(
                    'An account with this email already exists. Please sign in with your password.'
                );
            }
        }

        const hashedPassword = await hash(password);

        const user = await this.prisma.user.create({
            data: {
                firstname,
                lastname,
                email,
                password: hashedPassword,
                avatar,
                phone,
                method: 'CREDENTIALS',
            },
        });

        const tokens = await this.generateTokens(
            user.id,
            user.email,
            user.role
        );

        await this.saveRefreshToken(user.id, tokens.refreshToken);

        // Set refresh token as httpOnly cookie
        this.setRefreshTokenCookie(response, tokens.refreshToken);

        const { password: _, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async signupOrLoginWithGoogle(
        googleUser: GoogleUserData,
        response: Response
    ): Promise<AuthResponse> {
        const { email, firstname, lastname, avatar, googleId } = googleUser;

        let user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (user) {
            if (user.method === 'CREDENTIALS') {
                user = await this.prisma.user.update({
                    where: { id: user.id },
                    data: {
                        method: 'BOTH',
                        lastLogin: new Date(),
                        avatar: avatar || user.avatar,
                    },
                });

                await this.prisma.account.upsert({
                    where: {
                        provider_providerAccountId: {
                            provider: 'google',
                            providerAccountId: googleId,
                        },
                    },
                    create: {
                        userId: user.id,
                        type: 'oauth',
                        provider: 'google',
                        providerAccountId: googleId,
                        accessToken: googleUser.accessToken,
                        refreshToken: googleUser.refreshToken,
                        expiresAt: Math.floor(Date.now() / 1000) + 3600,
                        tokenType: 'Bearer',
                        scope: 'email profile',
                    },
                    update: {
                        accessToken: googleUser.accessToken,
                        refreshToken: googleUser.refreshToken,
                        expiresAt: Math.floor(Date.now() / 1000) + 3600,
                    },
                });
            } else {
                user = await this.prisma.user.update({
                    where: { id: user.id },
                    data: { lastLogin: new Date() },
                });
            }
        } else {
            user = await this.prisma.user.create({
                data: {
                    firstname,
                    lastname,
                    email,
                    avatar,
                    password: null,
                    method: 'GOOGLE',
                    isVerified: true,
                },
            });

            await this.prisma.account.create({
                data: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'google',
                    providerAccountId: googleId,
                },
            });
        }

        const tokens = await this.generateTokens(
            user.id,
            user.email,
            user.role
        );

        await this.saveRefreshToken(user.id, tokens.refreshToken);

        // Set refresh token as httpOnly cookie
        this.setRefreshTokenCookie(response, tokens.refreshToken);

        const { password: _, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async signin(
        dto: SigninRequest,
        response: Response
    ): Promise<AuthResponse> {
        const { email, password } = dto;

        const existUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!existUser) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Check if user has a password (might be Google-only account)
        if (!existUser.password) {
            throw new UnauthorizedException(
                'This account was created with Google. Please sign in with Google or add a password to your account.'
            );
        }

        // Verify password using argon2
        const isPasswordValid = await verify(existUser.password, password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Update last login
        const user = await this.prisma.user.update({
            where: { id: existUser.id },
            data: { lastLogin: new Date() },
        });

        // Generate tokens
        const tokens = await this.generateTokens(
            user.id,
            user.email,
            user.role
        );

        // Save refresh token
        await this.saveRefreshToken(user.id, tokens.refreshToken);

        // Set refresh token as httpOnly cookie
        this.setRefreshTokenCookie(response, tokens.refreshToken);

        // Remove password from response
        const { password: _, ...userWithoutPassword } = user;

        console.log('User signed in successfully');
        return {
            user: userWithoutPassword,
            accessToken: tokens.accessToken,
        };
    }

    async refreshTokens(
        request: Request,
        response: Response
    ): Promise<{ accessToken: string }> {
        const refreshToken = request.cookies['refreshToken'];

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not found');
        }

        // Verify refresh token
        try {
            const payload = await this.jwt.verifyAsync(refreshToken, {
                secret: this.config.get<string>('JWT_REFRESH_SECRET'),
            });

            // Check if refresh token exists in database and is not revoked
            const storedToken = await this.prisma.refreshToken.findFirst({
                where: {
                    token: refreshToken,
                    userId: payload.sub,
                    isRevoked: false,
                    expiresAt: { gt: new Date() },
                },
            });

            if (!storedToken) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            // Generate new tokens
            const newTokens = await this.generateTokens(
                payload.sub,
                payload.email,
                payload.role
            );

            // Revoke old refresh token
            await this.prisma.refreshToken.update({
                where: { id: storedToken.id },
                data: { isRevoked: true },
            });

            // Save new refresh token
            await this.saveRefreshToken(payload.sub, newTokens.refreshToken);

            // Set new refresh token cookie
            this.setRefreshTokenCookie(response, newTokens.refreshToken);

            return { accessToken: newTokens.accessToken };
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

    async logout(
        request: Request,
        response: Response
    ): Promise<{ message: string }> {
        const refreshToken = request.cookies['refreshToken'];

        if (refreshToken) {
            // Revoke refresh token in database
            await this.prisma.refreshToken.updateMany({
                where: {
                    token: refreshToken,
                    isRevoked: false,
                },
                data: {
                    isRevoked: true,
                },
            });
        }

        // Clear refresh token cookie
        response.clearCookie('refreshToken', {
            path: '/auth/refresh',
        });

        return { message: 'Logged out successfully' };
    }

    async logoutAll(
        userId: string,
        response: Response
    ): Promise<{ message: string }> {
        // Revoke all refresh tokens for the user
        await this.prisma.refreshToken.updateMany({
            where: {
                userId,
                isRevoked: false,
            },
            data: {
                isRevoked: true,
            },
        });

        // Clear refresh token cookie
        response.clearCookie('refreshToken', {
            path: '/auth/refresh',
        });

        return { message: 'Logged out from all devices successfully' };
    }

    async getSignInMethods(email: string): Promise<{
        hasPassword: boolean;
        hasGoogle: boolean;
        suggestedMethod: string;
    }> {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: {
                accounts: {
                    where: { provider: 'google' },
                },
            },
        });

        if (!user) {
            return {
                hasPassword: false,
                hasGoogle: false,
                suggestedMethod: 'signup',
            };
        }

        const hasPassword = !!user.password;
        const hasGoogle = user.accounts.length > 0 || user.method === 'GOOGLE';

        let suggestedMethod = 'password';
        if (user.method === 'GOOGLE' && !hasPassword) {
            suggestedMethod = 'google';
        } else if (hasGoogle && hasPassword) {
            suggestedMethod = 'both';
        }

        return {
            hasPassword,
            hasGoogle,
            suggestedMethod,
        };
    }

    async addPasswordToAccount(
        userId: string,
        password: string
    ): Promise<void> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        if (user.password) {
            throw new BadRequestException('Account already has a password');
        }

        const hashedPassword = await hash(password);

        await this.prisma.user.update({
            where: { id: userId },
            data: {
                password: hashedPassword,
                method: user.method === 'GOOGLE' ? 'BOTH' : 'CREDENTIALS',
            },
        });
    }

    async generateTokens(
        userId: string,
        email: string,
        role: string
    ): Promise<AuthTokens> {
        const payload = { sub: userId, email, role };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwt.signAsync(payload, {
                secret: this.config.get<string>('JWT_SECRET'),
                expiresIn:
                    this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') ||
                    '15m',
            }),
            this.jwt.signAsync(payload, {
                secret: this.config.get<string>('JWT_REFRESH_SECRET'),
                expiresIn:
                    this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') ||
                    '7d',
            }),
        ]);

        return { accessToken, refreshToken };
    }

    async saveRefreshToken(
        userId: string,
        refreshToken: string
    ): Promise<void> {
        await this.prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId,
                expiresAt: calculateExpiryDate(
                    this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') ||
                        '7d'
                ),
                isRevoked: false,
            },
        });
    }

    private setRefreshTokenCookie(
        response: Response,
        refreshToken: string
    ): void {
        response.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: this.config.get<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/auth/refresh',
        });
    }
}
