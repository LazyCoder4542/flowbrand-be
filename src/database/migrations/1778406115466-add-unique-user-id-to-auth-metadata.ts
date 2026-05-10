import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUniqueUserIdToAuthMetadata1778406115466 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "auth_metadata" ADD CONSTRAINT "UQ_auth_metadata_user_id" UNIQUE ("user_id")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "auth_metadata" DROP CONSTRAINT "UQ_auth_metadata_user_id"`
    );
  }
}
