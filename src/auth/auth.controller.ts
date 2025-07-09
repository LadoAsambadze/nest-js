import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterRequest } from './dto/register.dto';
import { AuthResponse } from './types/auth.types';
import { GoogleLoginRequest } from './dto/google-login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() dto: RegisterRequest): Promise<AuthResponse> {
        return await this.authService.register(dto);
    }


    @Post('google')
    @HttpCode(HttpStatus.CREATED)
    async googleLogin(@Body() dto: GoogleLoginRequest): Promise<AuthResponse> {
        return await this.authService.registerOrLoginWithGoogle(dto);
    }
}
