import { Args, Mutation, Resolver, Context } from '@nestjs/graphql';
import { HttpCode, HttpStatus } from '@nestjs/common';
import { SignupRequest } from './dto/signup.dto';
import { SigninRequest } from './dto/signin.dto';
import { AuthResponse } from './types/auth-response.type';
import { AccessTokenOutput } from './dto/accestoken-output.dto';

import { AuthService } from './auth.service';
import { MessageOutput } from './dto/message-output.dto';

@Resolver()
export class AuthResolver {
    constructor(private readonly authService: AuthService) {}

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
        @Args('signin') signinInput: SigninRequest,
        @Context() context: any
    ): Promise<AuthResponse> {
        return this.authService.signin(signinInput, context.res);
    }

    @Mutation(() => AccessTokenOutput, { name: 'refreshTokens' })
    @HttpCode(HttpStatus.OK)
    async refreshTokens(@Context() context: any): Promise<AccessTokenOutput> {
        const { accessToken } = await this.authService.refreshTokens(
            context.req,
            context.res
        );
        return { accessToken };
    }

    @Mutation(() => MessageOutput, { name: 'logout' })
    @HttpCode(HttpStatus.OK)
    async logout(@Context() context: any): Promise<MessageOutput> {
        await this.authService.logout(context.req, context.res);
        return { message: 'Logged out successfully' };
    }
}
