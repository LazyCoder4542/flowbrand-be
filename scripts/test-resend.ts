import * as nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';

dotenv.config();

const host = process.env.RESEND_SMTP_HOST ?? process.env.SMTP_HOST;
const port = Number(process.env.RESEND_SMTP_PORT ?? process.env.SMTP_PORT ?? 587);
const user = process.env.RESEND_SMTP_USER ?? process.env.SMTP_USER ?? 'resend';
const pass = process.env.RESEND_SMTP_API_KEY ?? process.env.SMTP_PASSWORD;
const from = process.env.MAIL_FROM ?? `"FlowBrand" <onboarding@resend.dev>`;

if (!pass) {
  console.error('No RESEND_SMTP_API_KEY or SMTP_PASSWORD found in .env');
  process.exit(1);
}

const TO = process.argv[2];
if (!TO) {
  console.error('Usage: npx ts-node scripts/test-resend.ts <recipient@email.com>');
  process.exit(1);
}

async function main() {
  console.log(`Connecting to ${host}:${port} as ${user} ...`);

  const transporter = nodemailer.createTransport({
    host,
    port,
    auth: { user, pass },
  });

  await transporter.verify();
  console.log('SMTP connection verified OK');

  const info = await transporter.sendMail({
    from,
    to: TO,
    subject: 'FlowBrand — Resend SMTP smoke test',
    html: '<p>If you see this, Resend SMTP is working correctly.</p>',
  });

  console.log('Email sent!');
  console.log('  Message ID:', info.messageId);
  console.log('  Accepted :', info.accepted);
}

main().catch(err => {
  console.error('SMTP error:', err.message);
  process.exit(1);
});
