import * as ms from 'ms';

export function calculateExpiryDate(expiration: string): Date {
    const now = new Date();

    try {
        const durationMs = ms(expiration as any);

        if (!durationMs || typeof durationMs !== 'number') {
            return new Date(now.getTime() + ms('7d' as any));
        }

        return new Date(now.getTime() + durationMs);
    } catch (error) {
        return new Date(now.getTime() + ms('7d' as any));
    }
}
