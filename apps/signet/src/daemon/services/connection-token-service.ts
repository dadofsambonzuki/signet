import crypto from 'crypto';
import prisma from '../../db.js';

// Lifetime (minutes) of a one-time `bunker://` connection token. Read from
// SIGNET_BUNKER_TOKEN_EXPIRY_MINUTES so a deployment can widen the coordination
// window around a pairing (e.g. relaying a URI across chat); invalid or
// non-positive values fall back to 5 minutes.
const DEFAULT_EXPIRY_MINUTES = (() => {
    const v = Number(process.env.SIGNET_BUNKER_TOKEN_EXPIRY_MINUTES);
    return Number.isFinite(v) && v > 0 ? v : 5;
})();

export interface ConnectionTokenResult {
    token: string;
    expiresAt: Date;
}

/**
 * Service for managing one-time connection tokens.
 * These tokens are used in bunker URIs as secrets and can only be used once.
 */
export class ConnectionTokenService {
    /**
     * Create a new one-time connection token.
     */
    async createToken(keyName: string, expiryMinutes: number = DEFAULT_EXPIRY_MINUTES): Promise<ConnectionTokenResult> {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);

        await prisma.connectionToken.create({
            data: {
                keyName,
                token,
                expiresAt,
            },
        });

        return { token, expiresAt };
    }

    /**
     * Validate and atomically redeem a connection token.
     * Returns true if the token was valid and successfully redeemed.
     * Returns false if the token is invalid, expired, or already used.
     */
    async validateAndRedeemToken(token: string, keyName: string): Promise<boolean> {
        const now = new Date();

        // Atomic update: only succeeds if token exists, matches keyName,
        // is not expired, and has not been redeemed yet
        const result = await prisma.connectionToken.updateMany({
            where: {
                token,
                keyName,
                expiresAt: { gt: now },
                redeemedAt: null,
            },
            data: {
                redeemedAt: now,
            },
        });

        return result.count > 0;
    }

    /**
     * Check if a token is valid without redeeming it.
     * Used for validation fallback logic.
     */
    async isTokenValid(token: string, keyName: string): Promise<boolean> {
        const now = new Date();

        const record = await prisma.connectionToken.findFirst({
            where: {
                token,
                keyName,
                expiresAt: { gt: now },
                redeemedAt: null,
            },
        });

        return record !== null;
    }

    /**
     * Clean up expired tokens.
     * Should be called periodically to prevent table bloat.
     */
    async cleanupExpiredTokens(): Promise<number> {
        const now = new Date();

        // Delete tokens that are either expired or were redeemed more than 1 hour ago
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

        const result = await prisma.connectionToken.deleteMany({
            where: {
                OR: [
                    { expiresAt: { lt: now } },
                    { redeemedAt: { lt: oneHourAgo } },
                ],
            },
        });

        return result.count;
    }
}

// Singleton instance
let connectionTokenService: ConnectionTokenService | null = null;

export function getConnectionTokenService(): ConnectionTokenService {
    if (!connectionTokenService) {
        connectionTokenService = new ConnectionTokenService();
    }
    return connectionTokenService;
}

export function setConnectionTokenService(service: ConnectionTokenService): void {
    connectionTokenService = service;
}
