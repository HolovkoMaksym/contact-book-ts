import { Injectable, UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'crypto';

import { SessionsRepository } from '../repositories/sessions.repository';
import { HashingService } from './hashing.service';
import { TokenService } from './token.service';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class SessionsService {
  private readonly refreshTtlMs = 7 * 24 * 60 * 60 * 1000;

  constructor(
    private readonly sessionsRepository: SessionsRepository,
    private readonly hashingService: HashingService,
    private readonly tokenService: TokenService,
  ) {}

  async createSession(
    userId: string,
    email: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<TokenPair> {
    const sessionId = randomUUID();
    const expiresAt = new Date(Date.now() + this.refreshTtlMs);

    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.generateAccessToken({ sub: userId, email }),
      this.tokenService.generateRefreshToken({ sub: userId, email, sessionId }),
    ]);

    const refreshTokenHash = await this.hashingService.hash(refreshToken);

    await this.sessionsRepository.create({
      id: sessionId,
      userId,
      refreshTokenHash,
      userAgent,
      ipAddress,
      expiresAt,
    });

    return { accessToken, refreshToken };
  }

  async rotateSession(refreshToken: string): Promise<TokenPair> {
    let payload;
    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const session = await this.sessionsRepository.findById(payload.sessionId);

    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    if (session.isRevoked) {
      await this.sessionsRepository.revokeAllForUser(session.userId);
      throw new UnauthorizedException(
        'Token reuse detected. All active sessions have been revoked.',
      );
    }

    if (session.expiresAt < new Date()) {
      await this.sessionsRepository.revoke(session.id);
      throw new UnauthorizedException('Session has expired');
    }

    const isTokenValid = await this.hashingService.compare(
      refreshToken,
      session.refreshTokenHash,
    );

    if (!isTokenValid) {
      await this.sessionsRepository.revokeAllForUser(session.userId);
      throw new UnauthorizedException(
        'Invalid refresh token. All active sessions have been revoked.',
      );
    }

    const newExpiresAt = new Date(Date.now() + this.refreshTtlMs);
    const [newAccessToken, newRefreshToken] = await Promise.all([
      this.tokenService.generateAccessToken({
        sub: payload.sub,
        email: payload.email,
      }),
      this.tokenService.generateRefreshToken({
        sub: payload.sub,
        email: payload.email,
        sessionId: session.id,
      }),
    ]);

    const newRefreshTokenHash = await this.hashingService.hash(newRefreshToken);
    await this.sessionsRepository.updateTokenHash(
      session.id,
      newRefreshTokenHash,
      newExpiresAt,
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async revokeSession(refreshToken: string): Promise<void> {
    try {
      const payload = await this.tokenService.verifyRefreshToken(refreshToken);
      await this.sessionsRepository.revoke(payload.sessionId);
    } catch {
    }
  }
}
