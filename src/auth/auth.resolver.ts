import { Args, Mutation, Resolver, Context } from '@nestjs/graphql';
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
import { AccessTokenOutput } from './dto/accesstoken-output.dto';
import { MessageOutput } from './dto/message-output.dto';
import { AuthService } from './services/auth.service';
import { ScheduledTasksService } from './services/sheduled-tasks.service';

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
        return this.authService.signup(signupInput, context.res);
    }

    @Mutation(() => AuthResponse, { name: 'signin' })
    @HttpCode(HttpStatus.OK)
    async signin(
        @Args('signinInput') signinInput: SigninRequest,
        @Context() context: any
    ): Promise<AuthResponse> {
        return this.authService.signin(signinInput, context.res);
    }

    @Mutation(() => AccessTokenOutput, { name: 'refreshAccessToken' })
    @HttpCode(HttpStatus.OK)
    async refreshAccessToken(@Context() context: any): Promise<AccessTokenOutput> {
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

        const { accessToken } = await this.authService.refreshAccessToken(req, res);
        return { accessToken };
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

    /**
     * Admin-only endpoint for manual token cleanup
     */
    @Mutation(() => MessageOutput, { name: 'cleanupTokens' })
    // @UseGuards(AdminGuard) // Ensure only admins can call this
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
}
