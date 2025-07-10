import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import {
    Strategy,
    type StrategyOptions,
    type VerifyCallback,
} from 'passport-google-oauth20';
import type { ConfigService } from '@nestjs/config';

export interface GoogleProfile {
    id: string;
    emails: { value: string; verified: boolean }[];
    name: { givenName: string; familyName: string };
    photos: { value: string }[];
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(private configService: ConfigService) {
        super({
            clientID: configService.get<string>('GOOGLE_CLIENT_ID')!,
            clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET')!,
            callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL')!,
            scope: ['email', 'profile'],
        } as StrategyOptions);
    }

    // ✅ This method processes Google's response and creates the user object
    async validate(
        accessToken: string,
        refreshToken: string,
        profile: GoogleProfile,
        done: VerifyCallback
    ): Promise<void> {
        const { id, emails, name, photos } = profile;

        // ✅ This object matches GoogleUserData interface in service
        const user = {
            googleId: id,
            email: emails[0].value,
            firstname: name.givenName,
            lastname: name.familyName,
            avatar: photos[0]?.value,
        };

        done(null, user);
    }
}
