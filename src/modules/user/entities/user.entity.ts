import { Column, DeleteDateColumn, Entity, Index } from 'typeorm';
import { AbstractBaseEntity } from '../../../entities/base.entity';

@Entity({ name: 'users' })
@Index('IDX_users_auth_provider_user', ['auth_provider', 'provider_user_id'], { unique: true })
export class User extends AbstractBaseEntity {
  @Column({ type: 'varchar', length: 100, nullable: false })
  full_name: string;

  @Column({ type: 'varchar', length: 255, unique: true, nullable: false })
  email: string;

  @Column({ type: 'text', nullable: true })
  password: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  country: string | null;

  @Column({ type: 'boolean', default: false })
  is_verified: boolean;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'text', nullable: true })
  avatar_url: string | null;

  @Column({ type: 'varchar', length: 20, nullable: false })
  auth_provider: string;

  @Column({ type: 'text', nullable: true })
  provider_user_id: string | null;

  @Column({ type: 'varchar', length: 6, nullable: true })
  otp_code: string | null;

  @Column({ type: 'timestamp', nullable: true })
  expires_at: Date | null;

  @Column({ type: 'boolean', nullable: false, default: false })
  terms_accepted: boolean;

  @DeleteDateColumn({ name: 'deleted_at', type: 'timestamp', nullable: true })
  deleted_at: Date | null;
}
