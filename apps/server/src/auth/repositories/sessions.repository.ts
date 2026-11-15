import { Session } from '@generated/prisma/client';

export interface CreateSessionData {
  id?: string;
  userId: string;
  refreshTokenHash: string;
  userAgent?: string;
  ipAddress?: string;
  expiresAt: Date;
}

export abstract class SessionsRepository {
  abstract create(data: CreateSessionData): Promise<Session>;
  abstract findById(id: string): Promise<Session | null>;
  abstract updateTokenHash(
    id: string,
    refreshTokenHash: string,
    expiresAt: Date,
  ): Promise<Session>;
  abstract revoke(id: string): Promise<Session>;
  abstract revokeAllForUser(userId: string): Promise<void>;
}
