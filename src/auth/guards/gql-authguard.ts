import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { TokenService } from '../services/token.service';
import { UserAccountService } from '../services/user-account.service';

@Injectable()
export class GqlAuthGuard implements CanActivate {
    constructor(
        private tokenService: TokenService,
        private userAccountService: UserAccountService
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const ctx = GqlExecutionContext.create(context);
        const request = ctx.getContext().req;
        const authHeader = request.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new UnauthorizedException('No access token found');
        }

        const accessToken = authHeader.substring(7);

        try {
            const payload = await this.tokenService.verifyAccessToken(accessToken);
            const user = await this.userAccountService.findById(payload.sub);
            if (!user) {
                throw new UnauthorizedException('User not found');
            }
            request.user = user;
            return true;
        } catch (error) {
            throw new UnauthorizedException('Invalid access token');
        }
    }
}
