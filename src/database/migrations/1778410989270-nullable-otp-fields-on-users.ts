import { MigrationInterface, QueryRunner } from 'typeorm';

export class NullableOtpFieldsOnUsers1778410989270 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "otp_code" DROP NOT NULL`);
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "expires_at" DROP NOT NULL`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "expires_at" SET NOT NULL`);
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "otp_code" SET NOT NULL`);
  }
}
