import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { AuthService } from '../services/auth.service';
import { GoogleRequest } from '../types/google-request.type';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth() {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req: GoogleRequest, @Res() res: Response) {
        try {
            const result = await this.authService.signupOrLoginWithGoogle(req, res);

            const redirectUrl = `http://localhost:5173/auth/success?token=${result.accessToken}`;

            res.redirect(redirectUrl);
        } catch (error) {
            console.error('❌ Google auth error:', error);
            const errorMessage = encodeURIComponent(error.message || 'Authentication failed');
            const errorUrl = `http://localhost:5173/auth/error?message=${errorMessage}`;
            res.redirect(errorUrl);
        }
    }

    @Get('logout')
    async logout(@Req() req: any, @Res() res: Response) {
        try {
            const result = await this.authService.logout(req, res);
            res.json(result);
        } catch (error) {
            res.status(400).json({
                message: error.message || 'Logout failed',
            });
        }
    }
}
