import {
    ConflictException,
    UnauthorizedException,
    BadRequestException,
    Injectable,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { hash, verify } from 'argon2';
import { SignupRequest } from '../dto/signup.dto';
import { GoogleUserData } from '../types/google-user.types';

@Injectable()
export class UserAccountService {
    constructor(private prisma: PrismaService) {}

    async createUserWithCredentials(dto: SignupRequest) {
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

        return user;
    }

    async signupOrLoginWithGoogle(googleUser: GoogleUserData) {
        const { email, firstname, lastname, avatar, googleId, accessToken, refreshToken } =
            googleUser;

        let user = await this.prisma.user.findUnique({ where: { email } });

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
                        accessToken,
                        refreshToken,
                        expiresAt: Math.floor(Date.now() / 1000) + 3600,
                        tokenType: 'Bearer',
                        scope: 'email profile',
                    },
                    update: {
                        accessToken,
                        refreshToken,
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

        return user;
    }

    async validateCredentials(email: string, password: string) {
        const user = await this.prisma.user.findUnique({ where: { email } });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!user.password) {
            throw new UnauthorizedException(
                'This account was created with Google. Please sign in with Google or add a password to your account.'
            );
        }

        const isValid = await verify(user.password, password);

        if (!isValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return await this.prisma.user.update({
            where: { id: user.id },
            data: { lastLogin: new Date() },
        });
    }
}
