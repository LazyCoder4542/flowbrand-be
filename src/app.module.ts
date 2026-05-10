import { BullModule } from '@nestjs/bull';
import { Module, ValidationPipe } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_PIPE } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as Joi from 'joi';
import { LoggerModule } from 'nestjs-pino';
import authConfig from '@config/auth.config';
import serverConfig from '@config/server.config';
import dataSource from '@database/data-source';
import { SeedingModule } from '@database/seeding/seeding.module';
import { AuthGuard } from '@guards/auth.guard';
import HealthController from './health.controller';
import { AuthModule } from '@modules/auth/auth.module';
import { EmailModule } from '@modules/email/email.module';
import { NotificationsModule } from '@modules/notifications/notifications.module';
import { UserModule } from '@modules/user/user.module';
import { WaitlistModule } from '@modules/waitlist/waitlist.module';
import { UploadedDocumentsModule } from '@modules/uploaded-documents/uploaded-documents.module';
import { StrategiesModule } from '@modules/strategies/strategies.module';
import { FunnelsModule } from '@modules/funnels/funnels.module';
import { WeeklyLogsModule } from '@modules/weekly-logs/weekly-logs.module';
import { SubscriptionsModule } from '@modules/subscriptions/subscriptions.module';
import ProbeController from './probe.controller';
import { RunTestsModule } from './run-tests/run-tests.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import { RedisModule } from '@modules/redis/redis.module';
import { join } from 'path';
import { ApiStatusModule } from '@modules/api-status/api-status.module';
import s3Config from '@config/s3.config';
import mailerConfig from '@config/mailer.config';

@Module({
  providers: [
    {
      provide: 'CONFIG',
      useClass: ConfigService,
    },
    {
      provide: APP_PIPE,
      useFactory: () =>
        new ValidationPipe({
          whitelist: true,
          forbidNonWhitelisted: true,
        }),
    },
    {
      provide: 'APP_GUARD',
      useClass: AuthGuard,
    },
  ],
  imports: [
    ConfigModule.forRoot({
      envFilePath: ['.env.development.local', `.env.${process.env.PROFILE}`],
      isGlobal: true,
      load: [serverConfig, authConfig, s3Config, mailerConfig],
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production', 'test', 'provision').required(),
        PROFILE: Joi.string().valid('local', 'development', 'production', 'ci', 'testing', 'staging').required(),
        PORT: Joi.number().required(),
      }),
    }),
    LoggerModule.forRoot(),
    TypeOrmModule.forRootAsync({
      useFactory: async () => ({
        ...dataSource.options,
      }),
      dataSourceFactory: async () => dataSource,
    }),
    SeedingModule,
    AuthModule,
    UserModule,
    EmailModule,
    BullModule.forRootAsync({
      useFactory: () => ({
        redis: {
          host: authConfig().redis.host,
          port: +authConfig().redis.port,
          password: authConfig().redis.password,
          username: authConfig().redis.username,
        },
      }),
    }),
    NotificationsModule,
    RunTestsModule,
    WaitlistModule,
    UploadedDocumentsModule,
    StrategiesModule,
    FunnelsModule,
    WeeklyLogsModule,
    SubscriptionsModule,
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, 'uploads'),
      serveRoot: '/uploads',
      serveStaticOptions: {
        index: false,
      },
    }),
    ApiStatusModule,
    RedisModule,
  ],
  controllers: [HealthController, ProbeController],
})
export class AppModule { }
