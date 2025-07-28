import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { AuthService } from '../services/auth.service';

interface GoogleRequest extends Request {
    user: {
        googleId: string;
        email: string;
        firstname: string;
        lastname: string;
        avatar?: string;
        accessToken?: string;
        refreshToken?: string;
    };
}

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
            const result = await this.authService.signupOrLoginWithGoogle(
                req.user,
                res // Pass response object
            );
            // Only use accessToken now, refresh token is in httpOnly cookie
            const redirectUrl = `${process.env.FRONTEND_URL}/auth/success?token=${result.accessToken}`;
            res.redirect(redirectUrl);
        } catch (error) {
            const errorMessage = encodeURIComponent(error.message);
            const errorUrl = `${process.env.FRONTEND_URL}/auth/error?message=${errorMessage}`;
            res.redirect(errorUrl);
        }
    }

    @Get('refresh')
    async refreshTokens(@Req() request: any, @Res() response: Response) {
        try {
            const result = await this.authService.refreshAccessToken(request, response);
            response.json(result);
        } catch (error) {
            response.status(401).json({ message: error.message });
        }
    }

    @Get('logout')
    async logout(@Req() req: any, @Res() res: Response) {
        try {
            const result = await this.authService.logout(req, res);
            res.json(result);
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    }
}
