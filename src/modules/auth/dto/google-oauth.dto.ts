export interface GoogleOAuthProfile {
  provider: string;
  providerId: string;
  email: string;
  full_name: string;
  avatar_url: string | null;
}

export interface OAuthLoginResponse {
  status_code: number;
  message: string;
  access_token: string;
  refresh_token: string;
  data: {
    user: {
      id: string;
      full_name: string;
      email: string;
      avatar_url: string | null;
    };
  };
}
