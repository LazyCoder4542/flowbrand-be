import { registerAs } from '@nestjs/config';

export default registerAs('mailer', () => {
  const smtpUser =
    process.env.RESEND_SMTP_USER ?? process.env.SMTP_USER ?? 'onboarding@resend.dev';

  return {
    host: process.env.RESEND_SMTP_HOST ?? process.env.SMTP_HOST,
    port: Number(process.env.RESEND_SMTP_PORT ?? process.env.SMTP_PORT ?? 587),
    user: smtpUser,
    pass: process.env.RESEND_SMTP_API_KEY ?? process.env.SMTP_PASSWORD,
    from: process.env.MAIL_FROM ?? `"FlowBrand" <${smtpUser}>`,
  };
});
