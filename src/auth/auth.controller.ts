import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Response } from 'express';
import type { AuthService } from './auth.service';

interface GoogleRequest extends Request {
    user: {
        googleId: string;
        email: string;
        firstname: string;
        lastname: string;
        avatar?: string;
    };
}

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth(@Req() req: GoogleRequest, @Res() res: Response) {
        // Initiates Google OAuth flow
        res.redirect('https://accounts.google.com/o/oauth2/auth');
    }

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req: GoogleRequest, @Res() res: Response) {
        try {
            const result = await this.authService.signupOrLoginWithGoogle(
                req.user
            );

            // Redirect to frontend with tokens or success message
            const redirectUrl = `${process.env.FRONTEND_URL}/auth/success?token=${result.tokens.accessToken}`;
            res.redirect(redirectUrl);
        } catch (error) {
            const errorUrl = `${process.env.FRONTEND_URL}/auth/error?message=${error.message}`;
            res.redirect(errorUrl);
        }
    }
}
