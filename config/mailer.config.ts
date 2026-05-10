import { registerAs } from '@nestjs/config';

export default registerAs('mailer', () => {
  const host = process.env.RESEND_SMTP_HOST ?? process.env.SMTP_HOST;
  const pass = process.env.RESEND_SMTP_API_KEY ?? process.env.SMTP_PASSWORD;
  const smtpUser = process.env.RESEND_SMTP_USER ?? process.env.SMTP_USER ?? 'onboarding@resend.dev';

  if (!host) throw new Error('Mailer config: RESEND_SMTP_HOST or SMTP_HOST is required');
  if (!pass) throw new Error('Mailer config: RESEND_SMTP_API_KEY or SMTP_PASSWORD is required');

  const fallbackFrom = smtpUser.includes('@')
    ? `"FlowBrand" <${smtpUser}>`
    : `"FlowBrand" <no-reply@${process.env.MAIL_DOMAIN ?? 'localhost'}>`;

  return {
    host,
    port: Number(process.env.RESEND_SMTP_PORT ?? process.env.SMTP_PORT ?? 587),
    user: smtpUser,
    pass,
    from: process.env.MAIL_FROM ?? fallbackFrom,
  };
});
