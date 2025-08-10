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
import { CurrentUser } from './current-user.decorator';
import { GqlAuthGuard } from './gql-authguard';
import { RefreshTokenResponse } from './types/refresh-token-response.type';

@Resolver()
export class AuthResolver {
    constructor(
        private readonly authService: AuthService,
        private readonly scheduledTasksService: ScheduledTasksService
    ) {}

    @Mutation(() => AuthResponse, { name: 'signup' })
    @HttpCode(HttpStatus.CREATED)
    async signup(
        @Args('signupInput') signupInput: SignupRequest,
        @Context() context: any
    ): Promise<AuthResponse> {
        const result = await this.authService.signup(signupInput, context.res);
        return result;
    }

    @Mutation(() => AuthResponse, { name: 'signin' })
    @HttpCode(HttpStatus.OK)
    async signin(
        @Args('signinInput') signinInput: SigninRequest,
        @Context() context: any
    ): Promise<AuthResponse> {
        const result = await this.authService.signin(signinInput, context.res);
        return result;
    }

    @Mutation(() => RefreshTokenResponse, { name: 'refreshToken' })
    @HttpCode(HttpStatus.OK)
    async refreshToken(@Context() context: any): Promise<RefreshTokenResponse> {
        const req = context.req as Request | undefined;
        const res = context.res as Response | undefined;

        if (!req) {
            throw new InternalServerErrorException('Request object not found in GraphQL context');
        }
        if (!res) {
            throw new InternalServerErrorException('Response object not found in GraphQL context');
        }
        if (!req.cookies) {
            throw new BadRequestException('No cookies found in request');
        }

        const result = await this.authService.refreshAccessToken(req, res);

        return result;
    }

    @Mutation(() => MessageOutput, { name: 'logout' })
    @HttpCode(HttpStatus.OK)
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
}
