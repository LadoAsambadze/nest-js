import { ConflictException, Injectable } from '@nestjs/common';
import type { JwtService } from '@nestjs/jwt';
import type { ConfigService } from '@nestjs/config';
import type { PrismaService } from '../prisma/prisma.service';
import { hash } from 'argon2';
import type { AuthTokens } from './types/auth-tokens.type';
import { calculateExpiryDate } from '../common/utils/expiry-date.util';
import type { AuthResponse } from './types/auth-response.type';
import type { SignupRequest } from './dto/signup.dto';

// ✅ Interface for Google user data from Passport.js
interface GoogleUserData {
    email: string;
    firstname: string;
    lastname: string;
    avatar?: string;
    googleId: string;
}

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}

    // ✅ Credentials signup - uses GraphQL DTO
    async signup(dto: SignupRequest): Promise<AuthResponse> {
        const { firstname, lastname, email, avatar, password, phone } = dto;

        const existingUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            throw new ConflictException('User with this email already exists');
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

        const { password: _, ...userWithoutPassword } = user;
        return { user: userWithoutPassword, tokens };
    }

    // ✅ Google OAuth - receives data from Passport.js (not GraphQL)
    async signupOrLoginWithGoogle(
        googleUser: GoogleUserData
    ): Promise<AuthResponse> {
        const { email, firstname, lastname, avatar, googleId } = googleUser;

        let user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (user) {
            // Existing user - just update last login
            user = await this.prisma.user.update({
                where: { id: user.id },
                data: { lastLogin: new Date() },
            });
        } else {
            // New user - create account
            user = await this.prisma.user.create({
                data: {
                    firstname,
                    lastname,
                    email,
                    avatar,
                    password: null, // No password for OAuth users
                    method: 'GOOGLE',
                    isVerified: true, // Google accounts are pre-verified
                },
            });

            // Create OAuth account record
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

        const { password: _, ...userWithoutPassword } = user;
        return { user: userWithoutPassword, tokens };
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
}
