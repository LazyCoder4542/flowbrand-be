import { MailerService } from '@nestjs-modules/mailer';
import { Process, Processor } from '@nestjs/bull';
import { MailInterface } from './interfaces/MailInterface';
import { Job } from 'bull';
import { Logger } from '@nestjs/common';

@Processor('emailSending')
export default class EmailQueueConsumer {
  private logger = new Logger(EmailQueueConsumer.name);
  constructor(private readonly mailerService: MailerService) {}

  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    if (!domain) return '***';
    const visible = local.length <= 2 ? '***' : `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`;
    return `${visible}@${domain}`;
  }

  private handleFailure(error: unknown, job: Job<MailInterface>, context: string): never {
    this.logger.error({
      message: `${context} failed`,
      error: error instanceof Error ? error.message : String(error),
      jobId: job.id,
      recipient: this.maskEmail(job.data?.mail?.to ?? ''),
    });
    throw error instanceof Error ? error : new Error(String(error));
  }

  @Process('welcome')
  async sendWelcomeEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;
      await this.mailerService.sendMail({
        ...mail,
        subject: 'Welcome to My App! Confirm your Email',
        template: 'Welcome-Template',
      });
      this.logger.log(`Welcome email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendWelcomeEmailJobError) {
      this.handleFailure(sendWelcomeEmailJobError, job, 'sendWelcomeEmailJob');
    }
  }

  @Process('waitlist')
  async sendWaitlistEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;

      await this.mailerService.sendMail({
        ...mail,
        subject: 'Waitlist Confirmation',
        template: 'waitlist',
      });
      this.logger.log(`Waitlist email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendWaitlistEmailJobError) {
      this.handleFailure(sendWaitlistEmailJobError, job, 'sendWaitlistEmailJob');
    }
  }

  @Process('reset-password')
  async sendResetPasswordEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;

      await this.mailerService.sendMail({
        ...mail,
        subject: 'Reset Password',
        template: 'Reset-Password-Template',
      });
      this.logger.log(`Reset password email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendResetPasswordEmailJobError) {
      this.handleFailure(sendResetPasswordEmailJobError, job, 'sendResetPasswordEmailJob');
    }
  }

  @Process('newsletter')
  async sendNewsletterEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;
      await this.mailerService.sendMail({
        ...mail,
        subject: 'Monthly Newsletter',
        template: 'newsletter',
      });
      this.logger.log(`Newsletter email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendNewsletterEmailJobError) {
      this.handleFailure(sendNewsletterEmailJobError, job, 'sendNewsletterEmailJob');
    }
  }

  @Process('register-otp')
  async sendTokenEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;
      await this.mailerService.sendMail({
        ...mail,
        subject: 'Verify your FlowBrand account',
        template: 'register-otp',
      });
      this.logger.log(`Register OTP email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendTokenEmailJobError) {
      this.handleFailure(sendTokenEmailJobError, job, 'sendTokenEmailJob');
    }
  }

  @Process('login-otp')
  async sendLoginOtpEmailJob(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;
      await this.mailerService.sendMail({
        ...mail,
        subject: 'Login with OTP',
        template: 'login-otp',
      });
      this.logger.log(`Login OTP email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendLoginOtpEmailJobError) {
      this.handleFailure(sendLoginOtpEmailJobError, job, 'sendLoginOtpEmailJob');
    }
  }

  @Process('in-app-notification')
  async sendNotificationMail(job: Job<MailInterface>) {
    try {
      const {
        data: { mail },
      } = job;

      await this.mailerService.sendMail({
        ...mail,
        subject: 'In-App, Notification',
        template: 'login-otp',
      });
      this.logger.log(`Notification email sent successfully to ${this.maskEmail(mail.to)}`);
    } catch (sendLoginOtpEmailJobError) {
      this.handleFailure(sendLoginOtpEmailJobError, job, 'sendNotificationMail');
    }
  }
}
