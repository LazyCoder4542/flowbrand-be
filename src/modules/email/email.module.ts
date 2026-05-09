import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/adapters/handlebars.adapter';
import { User } from '@modules/user/entities/user.entity';
import EmailQueueConsumer from './email.consumer';
import { EmailController } from './email.controller';
import { EmailService } from './email.service';
import QueueService from './queue.service';

@Module({
  providers: [EmailService, QueueService, EmailQueueConsumer],
  exports: [EmailService, QueueService],
  imports: [
    TypeOrmModule.forFeature([User]),
    BullModule.registerQueueAsync({
      name: 'emailSending',
    }),
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const smtpUser =
          configService.get<string>('RESEND_SMTP_USER') ??
          configService.get<string>('SMTP_USER') ??
          'onboarding@resend.dev';
        return {
          transport: {
            host: configService.get<string>('RESEND_SMTP_HOST') ?? configService.get<string>('SMTP_HOST'),
            port: Number(
              configService.get<string>('RESEND_SMTP_PORT') ?? configService.get<string>('SMTP_PORT') ?? 587
            ),
            auth: {
              user: smtpUser,
              pass: configService.get<string>('RESEND_SMTP_API_KEY') ?? configService.get<string>('SMTP_PASSWORD'),
            },
          },
          defaults: {
            from: configService.get<string>('MAIL_FROM') ?? `"FlowBrand" <${smtpUser}>`,
          },
          template: {
            dir: process.cwd() + '/src/modules/email/hng-templates',
            adapter: new HandlebarsAdapter(),
            options: {
              strict: true,
            },
          },
        };
      },
      inject: [ConfigService],
    }),
    ConfigModule,
  ],
  controllers: [EmailController],
})
export class EmailModule {}
