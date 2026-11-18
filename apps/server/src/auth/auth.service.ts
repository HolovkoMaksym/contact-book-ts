import {
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

import { UsersService } from '@/users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { HashingService } from './services/hashing.service';
import { SessionsService } from './services/sessions.service';

@Injectable()
export class AuthService {
  private readonly maxFailedAttempts = 5;
  private readonly lockDurationMs = 15 * 60 * 1000; 

  constructor(
    private readonly usersService: UsersService,
    private readonly hashingService: HashingService,
    private readonly sessionsService: SessionsService,
  ) {}

  async register(dto: RegisterDto, userAgent?: string, ipAddress?: string) {
    const existingUser = await this.usersService.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await this.hashingService.hash(dto.password);

    const user = await this.usersService.createUser({
      email: dto.email,
      name: dto.name,
      password: hashedPassword,
    });

    const tokens = await this.sessionsService.createSession(
      user.id,
      user.email,
      userAgent,
      ipAddress,
    );

    return {
      user: this.usersService.sanitizeUser(user),
      ...tokens,
    };
  }

  async login(dto: LoginDto, userAgent?: string, ipAddress?: string) {
    const user = await this.usersService.findByEmail(dto.email);

    if (!user || !user.password) {
      throw new UnauthorizedException('Invalid email or password');
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new ForbiddenException(
        'Account is temporarily locked due to multiple failed login attempts. Try again later.',
      );
    }

    const isPasswordValid = await this.hashingService.compare(
      dto.password,
      user.password,
    );

    if (!isPasswordValid) {
      const updatedUser = await this.usersService.registerFailedAttempt(
        user.id,
      );

      if (updatedUser.failedLoginAttempts >= this.maxFailedAttempts) {
        await this.usersService.lockUserAccount(
          user.id,
          new Date(Date.now() + this.lockDurationMs),
        );
      }

      throw new UnauthorizedException('Invalid email or password');
    }
    
    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      await this.usersService.resetSecurityLock(user.id);
    }

    const tokens = await this.sessionsService.createSession(
      user.id,
      user.email,
      userAgent,
      ipAddress,
    );

    return {
      user: this.usersService.sanitizeUser(user),
      ...tokens,
    };
  }

  async refresh(refreshToken: string) {
    return this.sessionsService.rotateSession(refreshToken);
  }

  async logout(refreshToken?: string) {
    if (refreshToken) {
      await this.sessionsService.revokeSession(refreshToken);
    }
  }
}
