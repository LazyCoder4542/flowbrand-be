import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { MailInterface } from './interfaces/MailInterface';
import { Injectable } from '@nestjs/common';

@Injectable()
export default class QueueService {
  constructor(
    @InjectQueue('emailSending')
    private readonly emailQueue: Queue
  ) {}

  async sendMail({ variant, mail }: MailSender) {
    const mailJob = await this.emailQueue.add(
      variant,
      { mail },
      { attempts: 3, backoff: { type: 'exponential', delay: 5000 } }
    );
    return { jobId: mailJob.id };
  }
}

export interface MailSender {
  mail: MailInterface;
  variant:
    | 'welcome'
    | 'waitlist'
    | 'newsletter'
    | 'reset-password'
    | 'login-otp'
    | 'register-otp'
    | 'in-app-notification';
}
