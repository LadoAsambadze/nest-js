import { Mutation, Resolver } from '@nestjs/graphql';
import { HttpCode, HttpStatus } from '@nestjs/common';
import type { AuthService } from './auth.service';
import type { SignupRequest } from './dto/signup.dto';
import { AuthResponse } from './types/auth-response.type';

@Resolver()
export class AuthResolver {
    constructor(private readonly authService: AuthService) {}

    @Mutation(() => AuthResponse, { name: 'signup' })
    @HttpCode(HttpStatus.CREATED)
    async signup(signupInput: SignupRequest): Promise<AuthResponse> {
        return await this.authService.signup(signupInput);
    }
}
