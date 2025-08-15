import { Args, Mutation, Resolver, Context, Query } from '@nestjs/graphql';
import {
    BadRequestException,
    HttpCode,
    HttpStatus,
    InternalServerErrorException,
    UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { SignupRequest } from './dto/signup.dto';
import { SigninRequest } from './dto/signin.dto';
import { AuthResponse } from './types/auth-response.type';
import { MessageOutput } from './dto/message-output.dto';
import { AuthService } from './services/auth.service';
import { ScheduledTasksService } from './services/sheduled-tasks.service';
import { User } from './types/user.type';
import { CurrentUser } from './decorators/current-user.decorator';
import { GqlAuthGuard } from './guards/gql-authguard';
import { RefreshTokenResponse } from './types/refresh-token-response.type';
import { UserAccountService } from './services/user-account.service';
import { SignupResponse } from './types/signup-response.type';
import { UpdatePasswordResponse } from './types/update-password-response.type';
import { UpdatePasswordInput } from './dto/update-password.dto';
import { validateContext } from './helpers/validate-context.helper';

@Resolver()
export class AuthResolver {
    constructor(
        private readonly authService: AuthService,
        private readonly scheduledTasksService: ScheduledTasksService,
        private readonly userAccountService: UserAccountService
    ) {}

    @Mutation(() => SignupResponse, { name: 'signup' })
    async signup(@Args('signupInput') dto: SignupRequest): Promise<SignupResponse> {
        try {
            const result = await this.authService.signup(dto);
            return {
                success: true,
                message:
                    'Account created successfully. Please check your email to verify your account.',
                userId: result.id,
                email: result.email,
            };
        } catch (error) {
            throw new BadRequestException(error.message || 'Signup failed');
        }
    }

    @Mutation(() => AuthResponse, { name: 'signin' })
    @HttpCode(HttpStatus.OK)
    async signin(
        @Args('signinInput') dto: SigninRequest,
        @Context() context: any
    ): Promise<AuthResponse> {
        const result = await this.authService.signin(dto, context.res);
        return result;
    }

    @Mutation(() => RefreshTokenResponse, { name: 'refreshToken' })
    async refreshToken(@Context() context: any): Promise<RefreshTokenResponse> {
        const { req, res } = validateContext(context);

        if (!req.cookies) {
            throw new BadRequestException('No cookies found in request');
        }

        return await this.authService.refreshAccessToken(req, res);
    }

    @Mutation(() => MessageOutput, { name: 'logout' })
    @HttpCode(HttpStatus.NO_CONTENT)
    async logout(@Context() context: any): Promise<MessageOutput> {
        const req = context.req as Request;
        const res = context.res as Response;

        if (!req) {
            throw new InternalServerErrorException('Request object not found in GraphQL context');
        }
        if (!res) {
            throw new InternalServerErrorException('Response object not found in GraphQL context');
        }

        const result = await this.authService.logout(req, res);

        return result;
    }

    @Mutation(() => MessageOutput, { name: 'cleanupTokens' })
    async cleanupTokens(): Promise<MessageOutput> {
        const result = await this.scheduledTasksService.manualTokenCleanup();

        if (result.success) {
            return {
                message: `Successfully cleaned up ${result.deletedCount} expired tokens`,
            };
        } else {
            throw new Error(`Token cleanup failed: ${result.error}`);
        }
    }

    @Query(() => User, { name: 'me' })
    @UseGuards(GqlAuthGuard)
    async me(@CurrentUser() user: User): Promise<User> {
        return user;
    }

    @Query(() => String)
    async verifyEmail(@Args('token') token: string) {
        if (!token || token.trim().length === 0) {
            throw new BadRequestException('Token is required');
        }
        const result = await this.userAccountService.verifyEmail(token);
        return result.message;
    }

    @Mutation(() => String)
    async resendVerificationEmail(@Args('email') email: string) {
        const result = await this.userAccountService.resendVerificationEmail(email);
        return result.message;
    }

    @Mutation(() => String)
    async sendUpdatePasswordEmail(@Args('email') email: string) {
        const result = await this.userAccountService.sendUpdatePasswordEmail(email);
        return result;
    }

    @Mutation(() => UpdatePasswordResponse)
    async updatePassword(@Args('data') dto: UpdatePasswordInput): Promise<UpdatePasswordResponse> {
        await this.userAccountService.updatePassword(dto);
        return { message: 'Password updated successfully' };
    }
}
