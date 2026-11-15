import { Injectable } from '@nestjs/common';

import { PrismaService } from '@/prisma/prisma.service';
import { CreateSessionData, SessionsRepository } from './sessions.repository';

@Injectable()
export class PrismaSessionsRepository extends SessionsRepository {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async create(data: CreateSessionData) {
    return this.prisma.session.create({ data });
  }

  async findById(id: string) {
    return this.prisma.session.findUnique({ where: { id } });
  }

  async updateTokenHash(id: string, refreshTokenHash: string, expiresAt: Date) {
    return this.prisma.session.update({
      where: { id },
      data: { refreshTokenHash, expiresAt },
    });
  }

  async revoke(id: string) {
    return this.prisma.session.update({
      where: { id },
      data: { isRevoked: true },
    });
  }

  async revokeAllForUser(userId: string) {
    await this.prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true },
    });
  }
}
