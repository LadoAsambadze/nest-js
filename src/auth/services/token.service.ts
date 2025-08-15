import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { AuthTokens } from '../types/auth-tokens.type';
import { calculateExpiryDate } from '../../common/utils/expiry-date.util';

@Injectable()
export class TokenService {
    private readonly logger = new Logger(TokenService.name);
    constructor(
        private jwt: JwtService,
        private config: ConfigService,
        private prisma: PrismaService
    ) {}

    async generateTokens(
        userId: string,
        email: string,
        role: string,
        firstname?: string,
        lastname?: string,
        avatar?: string
    ): Promise<AuthTokens> {
        const payload = {
            sub: userId,
            email,
            role,
            firstname,
            lastname,
            avatar,
        };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwt.signAsync(payload, {
                secret: this.config.get<string>('JWT_SECRET'),
                expiresIn: this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') || '15m',
            }),
            this.jwt.signAsync(payload, {
                secret: this.config.get<string>('JWT_REFRESH_SECRET'),
                expiresIn: this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') || '7d',
            }),
        ]);

        return { accessToken, refreshToken };
    }

    async generateAccessToken(
        userId: string,
        email: string,
        role: string,
        firstname?: string,
        lastname?: string,
        avatar?: string
    ): Promise<string> {
        const payload = {
            sub: userId,
            email,
            role,
            firstname,
            lastname,
            avatar,
        };

        return this.jwt.signAsync(payload, {
            secret: this.config.get<string>('JWT_SECRET'),
            expiresIn: this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') || '15m',
        });
    }

    async verifyRefreshToken(token: string) {
        try {
            const payload = await this.jwt.verifyAsync(token, {
                secret: this.config.get<string>('JWT_REFRESH_SECRET'),
            });

            const storedToken = await this.prisma.session.findFirst({
                where: {
                    token,
                    userId: payload.sub,
                    isRevoked: false,
                    expiresAt: { gt: new Date() },
                },
            });

            if (!storedToken) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            return { payload, storedToken };
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

    async saveRefreshToken(userId: string, refreshToken: string): Promise<void> {
        await this.prisma.session.upsert({
            where: { token: refreshToken },
            update: {
                userId,
                expiresAt: calculateExpiryDate(
                    this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') || '7d'
                ),
                isRevoked: false,
            },
            create: {
                token: refreshToken,
                userId,
                expiresAt: calculateExpiryDate(
                    this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') || '7d'
                ),
                isRevoked: false,
            },
        });
    }

    async isRefreshTokenNearExpiry(token: string, thresholdDays: number = 1): Promise<boolean> {
        const storedToken = await this.prisma.session.findFirst({
            where: { token, isRevoked: false },
        });

        if (!storedToken) return true;

        const now = new Date();
        const thresholdMs = thresholdDays * 24 * 60 * 60 * 1000;
        const threshold = new Date(now.getTime() + thresholdMs);

        return storedToken.expiresAt <= threshold;
    }

    async revokeRefreshTokenById(id: string) {
        await this.prisma.session.update({
            where: { id },
            data: { isRevoked: true },
        });
    }

    async revokeRefreshToken(token: string) {
        await this.prisma.session.updateMany({
            where: {
                token,
                isRevoked: false,
            },
            data: {
                isRevoked: true,
            },
        });
    }

    async revokeAllUserTokens(userId: string) {
        await this.prisma.session.updateMany({
            where: {
                userId,
                isRevoked: false,
            },
            data: {
                isRevoked: true,
            },
        });
    }

    async cleanupExpiredTokens(): Promise<{ deletedCount: number }> {
        try {
            const result = await this.prisma.session.deleteMany({
                where: {
                    OR: [{ expiresAt: { lt: new Date() } }, { isRevoked: true }],
                },
            });

            this.logger.log(`Cleaned up ${result.count} expired/revoked tokens`);
            return { deletedCount: result.count };
        } catch (error) {
            this.logger.error('Failed to cleanup expired tokens', error);
            throw error;
        }
    }

    async verifyAccessToken(token: string) {
        try {
            return await this.jwt.verifyAsync(token, {
                secret: this.config.get<string>('JWT_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid access token');
        }
    }

    async getTokenStats(): Promise<{
        totalSessions: number;
        activeSessions: number;
        expiredSessions: number;
        revokedSessions: number;
    }> {
        const now = new Date();

        const [totalSessions, activeSessions, expiredSessions, revokedSessions] = await Promise.all(
            [
                this.prisma.session.count(),
                this.prisma.session.count({
                    where: {
                        isRevoked: false,
                        expiresAt: { gt: now },
                    },
                }),
                this.prisma.session.count({
                    where: {
                        isRevoked: false,
                        expiresAt: { lte: now },
                    },
                }),
                this.prisma.session.count({
                    where: { isRevoked: true },
                }),
            ]
        );

        return {
            totalSessions,
            activeSessions,
            expiredSessions,
            revokedSessions,
        };
    }
}
