import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes, createHash } from 'crypto';
import { User } from '@modules/user/entities/user.entity';
import { UserSession } from './entities/user-session.entity';

const REFRESH_TOKEN_EXPIRY_DAYS = Number(process.env.REFRESH_TOKEN_EXPIRY ?? 7);
@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(UserSession)
    private readonly repo: Repository<UserSession>
  ) {}

  async create(user: User): Promise<{ rawToken: string; sessionId: string }> {
    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

    const session = await this.repo.save(
      this.repo.create({
        user_id: user.id,
        refresh_token: hashedToken,
        expires_at: expiresAt,
        is_revoked: false,
      })
    );

    return { rawToken, sessionId: session.id };
  }
}
