import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(
        private configService: ConfigService,
        private authService: AuthService
    ) {
        const clientID = configService.get('GOOGLE_CLIENT_ID');
        const clientSecret = configService.get('GOOGLE_CLIENT_SECRET');
        const callbackURL = configService.get('GOOGLE_CALLBACK_URL');

        if (!clientID || !clientSecret || !callbackURL) {
            throw new Error(
                'Missing Google OAuth configuration. Please check your environment variables.'
            );
        }

        super({
            clientID,
            clientSecret,
            callbackURL,
            scope: ['email', 'profile'],
        });
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: any,
        done: VerifyCallback
    ): Promise<any> {
        const { name, emails, photos, id } = profile;

        const user = {
            email: emails[0].value,
            firstname: name.givenName,
            lastname: name.familyName,
            avatar: photos[0].value,
            googleId: id,
            accessToken: accessToken,
            refreshToken: refreshToken,
        };

        done(null, user);
    }
}
