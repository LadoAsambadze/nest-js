import { ConflictException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import { hash } from 'argon2';
import { AuthTokens } from './types/auth-tokens.type';
import { calculateExpiryDate } from 'src/common/utils/expiry-date.util';
import { AuthResponse } from './types/auth-response.type';
import { SignupRequest } from './dto/signup.dto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}

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

    async signupOrLoginWithGoogle(googleUser: {
        email: string;
        firstname: string;
        lastname: string;
        avatar?: string;
        googleId: string;
    }): Promise<AuthResponse> {
        const { email, firstname, lastname, avatar, googleId } = googleUser;

        let user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (user) {
            user = await this.prisma.user.update({
                where: { id: user.id },
                data: { lastLogin: new Date() },
            });
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
