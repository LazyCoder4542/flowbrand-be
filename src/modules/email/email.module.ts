import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import mailerConfig from '@config/mailer.config';
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
      useFactory: () => {
        const cfg = mailerConfig();
        return {
          transport: {
            host: cfg.host,
            port: cfg.port,
            auth: { user: cfg.user, pass: cfg.pass },
          },
          defaults: { from: cfg.from },
          template: {
            dir: process.cwd() + '/src/modules/email/hng-templates',
            adapter: new HandlebarsAdapter(),
            options: { strict: true },
          },
        };
      },
    }),
  ],
  controllers: [EmailController],
})
export class EmailModule {}
