import {
    ConflictException,
    UnauthorizedException,
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { hash, verify } from 'argon2';
import { SignupRequest } from '../dto/signup.dto';
import { User } from '../types/user.type';
import * as crypto from 'crypto';
import { EmailService } from './email.service';
import { UpdatePasswordInput } from '../dto/update-password.dto';
import { GoogleRequest } from '../types/google-request.type';

@Injectable()
export class UserAccountService {
    constructor(
        private prisma: PrismaService,
        private emailService: EmailService
    ) {}

    async createUserWithCredentials(dto: SignupRequest) {
        const { firstname, lastname, email, avatar, password, phone } = dto;

        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

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
                emailVerificationToken: emailVerificationToken,
                emailVerificationExpires: emailVerificationExpires,
            },
        });

        try {
            await this.emailService.sendVerificationEmail(
                user.email,
                user.firstname,
                emailVerificationToken
            );
        } catch (error) {
            console.error('Failed to send verification email:', error);
        }

        const { password: _, emailVerificationToken: __, ...userWithoutSensitiveData } = user;
        return userWithoutSensitiveData;
    }

    async verifyEmail(token: string) {
        const user = await this.prisma.user.findFirst({
            where: {
                emailVerificationToken: token,
                emailVerificationExpires: {
                    gt: new Date(),
                },
                isVerified: false,
            },
        });

        if (!user) {
            throw new BadRequestException('Invalid or expired verification token');
        }

        const updatedUser = await this.prisma.user.update({
            where: {
                id: user.id,
            },
            data: {
                isVerified: true,
                emailVerificationToken: null,
                emailVerificationExpires: null,
            },
        });

        return {
            message: 'Email verified successfully',
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                isVerified: updatedUser.isVerified,
            },
        };
    }

    async resendVerificationEmail(email: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                email,
            },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        if (user.isVerified) {
            throw new BadRequestException('Email is already verified');
        }

        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                emailVerificationToken: emailVerificationToken,
                emailVerificationExpires: emailVerificationExpires,
            },
        });

        await this.emailService.sendVerificationEmail(
            user.email,
            user.firstname,
            emailVerificationToken
        );

        return { message: 'Verification email sent successfully' };
    }

    async signupOrLoginWithGoogle(req: GoogleRequest) {
        const { email, firstname, lastname, avatar, googleId } = req.user;

        let user = await this.prisma.user.findUnique({ where: { email } });

        if (user) {
            if (user.method === 'CREDENTIALS') {
                user = await this.prisma.user.update({
                    where: { id: user.id },
                    data: {
                        method: 'BOTH',
                        lastLogin: new Date(),
                        avatar: avatar || user.avatar,
                        isVerified: true,
                    },
                });
            } else {
                user = await this.prisma.user.update({
                    where: { id: user.id },
                    data: {
                        lastLogin: new Date(),
                        avatar: avatar || user.avatar,
                    },
                });
            }

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
                    expiresAt: Math.floor(Date.now() / 1000) + 3600,
                    tokenType: 'Bearer',
                    scope: 'email profile',
                },
                update: {
                    expiresAt: Math.floor(Date.now() / 1000) + 3600,
                },
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
                    expiresAt: Math.floor(Date.now() / 1000) + 3600,
                    tokenType: 'Bearer',
                    scope: 'email profile',
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

        if (!user.isVerified) {
            throw new UnauthorizedException('User is not verified, please check you email');
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

    async findById(userId: string): Promise<User> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                firstname: true,
                lastname: true,
                email: true,
                role: true,
                isVerified: true,
                isActive: true,
                avatar: true,
                phone: true,
                lastLogin: true,
                createdAt: true,
                updatedAt: true,
                method: true,
                password: false,
            },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return user as User;
    }

    async findByEmail(email: string) {
        return await this.prisma.user.findUnique({
            where: { email },
            select: {
                id: true,
                email: true,
                firstname: true,
                lastname: true,
                role: true,
                avatar: true,
                phone: true,
                method: true,
                isVerified: true,
                lastLogin: true,
                createdAt: true,
                updatedAt: true,
            },
        });
    }

    async updateLastLogin(userId: string) {
        return await this.prisma.user.update({
            where: { id: userId },
            data: { lastLogin: new Date() },
            select: {
                id: true,
                email: true,
                firstname: true,
                lastname: true,
                role: true,
                avatar: true,
                phone: true,
                method: true,
                isVerified: true,
                lastLogin: true,
                createdAt: true,
                updatedAt: true,
            },
        });
    }

    async sendUpdatePasswordEmail(email: string) {
        const user = await this.prisma.user.findUnique({ where: { email } });

        const TOKEN_EXPIRATION_MINUTES = 60;

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + TOKEN_EXPIRATION_MINUTES * 60 * 1000);

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                resetPasswordToken: token,
                resetPasswordTokenExpires: expiresAt,
            },
        });

        try {
            await this.emailService.sendUpdatePasswordEmail(email, token);
        } catch (error) {
            console.error('Failed to send update password email:', error);
            throw error;
        }

        return 'Update password link on  email sent successfully';
    }

    async updatePassword(dto: UpdatePasswordInput) {
        const user = await this.prisma.user.findFirst({
            where: {
                resetPasswordToken: dto.token,
            },
        });

        if (!user) {
            throw new UnauthorizedException('User with this token not found');
        }

        const hashedPassword = await hash(dto.password);
        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                resetPasswordToken: null,
                resetPasswordTokenExpires: null,
            },
        });

        return 'Update password ';
    }
}
