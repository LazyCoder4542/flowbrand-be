import { MigrationInterface, QueryRunner } from 'typeorm';

export class Migration1778335054510 implements MigrationInterface {
  name = 'Migration1778335054510';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "terms_accepted" boolean NOT NULL DEFAULT false`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "terms_accepted"`);
  }
}
