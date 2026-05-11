import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthMetadata } from './entities/auth-metadata.entity';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

@Injectable()
export class LockoutService {
  constructor(
    @InjectRepository(AuthMetadata)
    private readonly repo: Repository<AuthMetadata>
  ) {}

  async findOrCreate(userId: string): Promise<AuthMetadata> {
    const existing = await this.repo.findOneBy({ user_id: userId });
    if (existing) return existing;
    return this.repo.save(this.repo.create({ user_id: userId, failed_attempts: 0 }));
  }

  isLocked(meta: AuthMetadata): boolean {
    return meta.locked_until !== null && meta.locked_until > new Date();
  }

  secondsRemaining(meta: AuthMetadata): number {
    return Math.ceil((meta.locked_until!.getTime() - Date.now()) / 1000);
  }

  async recordFailure(meta: AuthMetadata): Promise<void> {
    const lockExpired = meta.locked_until !== null && meta.locked_until < new Date();
    meta.failed_attempts = lockExpired ? 1 : meta.failed_attempts + 1;
    if (meta.failed_attempts >= MAX_FAILED_ATTEMPTS) {
      meta.locked_until = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
    }
    await this.repo.save(meta);
  }

  async clear(meta: AuthMetadata): Promise<void> {
    meta.failed_attempts = 0;
    meta.locked_until = null;
    meta.last_login_at = new Date();
    await this.repo.save(meta);
  }
}
