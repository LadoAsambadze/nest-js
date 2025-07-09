import ms from 'ms';

export function calculateExpiryDate(expiration: string): Date {
    const now = new Date();
    const durationMs = ms(expiration as any);

    if (!durationMs) {
        return new Date(now.getTime() + ms('7d' as any));
    }

    return new Date(now.getTime() + durationMs);
}
