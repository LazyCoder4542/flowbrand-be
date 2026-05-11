import { MigrationInterface, QueryRunner } from 'typeorm';

export class Migration1778323146003 implements MigrationInterface {
  name = 'Migration1778323146003';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "auth_metadata" ADD "failed_attempts" integer NOT NULL DEFAULT '0'`);
    await queryRunner.query(`ALTER TYPE "public"."user_roles_role_enum" RENAME TO "user_roles_role_enum_old"`);
    await queryRunner.query(`CREATE TYPE "public"."user_roles_role_enum" AS ENUM('user', 'admin')`);
    await queryRunner.query(`ALTER TABLE "user_roles" ALTER COLUMN "role" DROP DEFAULT`);
    await queryRunner.query(
      `ALTER TABLE "user_roles" ALTER COLUMN "role" TYPE "public"."user_roles_role_enum" USING "role"::"text"::"public"."user_roles_role_enum"`
    );
    await queryRunner.query(`ALTER TABLE "user_roles" ALTER COLUMN "role" SET DEFAULT 'user'`);
    await queryRunner.query(`DROP TYPE "public"."user_roles_role_enum_old"`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TYPE "public"."user_roles_role_enum_old" AS ENUM('user', 'admin')`);
    await queryRunner.query(`ALTER TABLE "user_roles" ALTER COLUMN "role" DROP DEFAULT`);
    await queryRunner.query(
      `ALTER TABLE "user_roles" ALTER COLUMN "role" TYPE "public"."user_roles_role_enum_old" USING "role"::"text"::"public"."user_roles_role_enum_old"`
    );
    await queryRunner.query(`ALTER TABLE "user_roles" ALTER COLUMN "role" SET DEFAULT 'user'`);
    await queryRunner.query(`DROP TYPE "public"."user_roles_role_enum"`);
    await queryRunner.query(`ALTER TYPE "public"."user_roles_role_enum_old" RENAME TO "user_roles_role_enum"`);
    await queryRunner.query(`ALTER TABLE "auth_metadata" DROP COLUMN "failed_attempts"`);
  }
}
