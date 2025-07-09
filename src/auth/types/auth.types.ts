export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export interface AuthResponse {
    user: {
        id: string;
        firstname: string;
        lastname: string;
        email: string;
        role: string;
        isVerified: boolean;
        isActive: boolean;
        avatar: string | null;
        phone: string | null;
        createdAt: Date;
        updatedAt: Date;
        lastLogin: Date | null;
    };
    tokens: AuthTokens;
}

export interface RefreshTokenValidation {
    userId: string;
    email: string;
    role: string;
}
