import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { TokenService } from './services/token.service';
import { UserAccountService } from './services/user-account.service';

@Injectable()
export class GqlAuthGuard implements CanActivate {
    constructor(
        private tokenService: TokenService,
        private userAccountService: UserAccountService
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const ctx = GqlExecutionContext.create(context);
        const request = ctx.getContext().req;

        // Extract token from Authorization header
        const authHeader = request.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new UnauthorizedException('No access token found');
        }

        const accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix

        try {
            // Verify access token
            const payload = await this.tokenService.verifyAccessToken(accessToken);

            // Fetch user and attach to context
            const user = await this.userAccountService.findById(payload.sub);
            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            // Attach user to context for @CurrentUser decorator
            request.user = user;
            return true;
        } catch (error) {
            throw new UnauthorizedException('Invalid access token');
        }
    }
}
