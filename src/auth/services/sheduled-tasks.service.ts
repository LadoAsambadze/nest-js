import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TokenService } from './token.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ScheduledTasksService {
    private readonly logger = new Logger(ScheduledTasksService.name);

    constructor(
        private readonly tokenService: TokenService,
        private readonly configService: ConfigService
    ) {}

    @Cron('0 0 * * *', {
        name: 'cleanupExpiredTokens',
        timeZone: 'UTC',
    })
    async handleTokenCleanup() {
        const isEnabled = this.configService.get<boolean>('TOKEN_CLEANUP_ENABLED', true);

        if (!isEnabled) {
            this.logger.log('Token cleanup is disabled');
            return;
        }
        this.logger.log('Starting scheduled token cleanup...');

        try {
            const result = await this.tokenService.cleanupExpiredTokens();
            this.logger.log(`Token cleanup completed: ${result.deletedCount} tokens removed`);
        } catch (error) {
            this.logger.error('Token cleanup failed', error);
        }
    }

    @Cron('0 1 * * 0', {
        name: 'logTokenStats',
        timeZone: 'UTC',
    })
    async handleTokenStatsLogging() {
        this.logger.log('Generating token statistics...');

        try {
            const stats = await this.tokenService.getTokenStats();
            this.logger.log('Token Statistics:', {
                total: stats.totalSessions,
                active: stats.activeSessions,
                expired: stats.expiredSessions,
                revoked: stats.revokedSessions,
            });
        } catch (error) {
            this.logger.error('Failed to generate token statistics', error);
        }
    }

    async manualTokenCleanup(): Promise<{
        success: boolean;
        deletedCount: number;
        error?: string;
    }> {
        try {
            const result = await this.tokenService.cleanupExpiredTokens();
            return { success: true, deletedCount: result.deletedCount };
        } catch (error) {
            this.logger.error('Manual token cleanup failed', error);
            return {
                success: false,
                deletedCount: 0,
                error: error.message,
            };
        }
    }
}
