import { Body, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupRequest } from './dto/signup.dto';
import { GoogleLoginRequest } from './dto/google-login.dto';
import { Args, Mutation, Resolver } from '@nestjs/graphql';
import { AuthResponse } from './types/auth-response.type';

@Resolver()
export class AuthResolver {
    constructor(private readonly authService: AuthService) {}

    @Mutation(() => AuthResponse, { name: 'signup' })
    @HttpCode(HttpStatus.CREATED)
    async signup(
        @Args('signupInput') signupInput: SignupRequest
    ): Promise<AuthResponse> {
        return await this.authService.signup(signupInput);
    }

    @Mutation(() => AuthResponse, { name: 'google' })
    @HttpCode(HttpStatus.CREATED)
    async googleLogin(
        @Args('googleLoginInput') dto: GoogleLoginRequest
    ): Promise<AuthResponse> {
        return await this.authService.signupOrLoginWithGoogle(dto);
    }
}
