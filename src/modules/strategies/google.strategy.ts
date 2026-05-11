import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import authConfig from '@config/auth.config';
import { GoogleOAuthProfile } from '@modules/auth/dto/google-oauth.dto';
import * as SYS_MSG from '@shared/constants/SystemMessages';

interface PassportGoogleProfile {
  id: string;
  displayName?: string;
  emails?: Array<{ value: string; verified?: boolean }>;
  photos?: Array<{ value: string }>;
  name?: { givenName?: string; familyName?: string };
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    const cfg = authConfig().google;
    if (!cfg.clientID || !cfg.clientSecret || !cfg.callbackURL) {
      throw new Error(
        'Missing Google OAuth environment variables (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI)'
      );
    }

    super({
      clientID: cfg.clientID,
      clientSecret: cfg.clientSecret,
      callbackURL: cfg.callbackURL,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: PassportGoogleProfile,
    done: VerifyCallback
  ): Promise<void> {
    if (!profile || !profile.emails || !profile.emails.length) {
      return done(new UnauthorizedException(SYS_MSG.GOOGLE_ACCOUNT_NO_EMAIL), false);
    }

    const email = profile.emails[0].value;
    const user: GoogleOAuthProfile = {
      provider: 'google',
      providerId: profile.id,
      email,
      full_name: profile.displayName || `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim(),
      avatar_url: profile.photos && profile.photos.length ? profile.photos[0].value : null,
    };

    return done(null, user);
  }
}
