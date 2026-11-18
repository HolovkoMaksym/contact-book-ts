import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { UsersModule } from '@/users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaSessionsRepository } from './repositories/prisma-sessions.repository';
import { SessionsRepository } from './repositories/sessions.repository';
import { HashingService } from './services/hashing.service';
import { SessionsService } from './services/sessions.service';
import { TokenService } from './services/token.service';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [UsersModule, PassportModule, JwtModule.register({})],
  controllers: [AuthController],
  providers: [
    AuthService,
    HashingService,
    TokenService,
    SessionsService,
    JwtStrategy,
    {
      provide: SessionsRepository,
      useClass: PrismaSessionsRepository,
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
