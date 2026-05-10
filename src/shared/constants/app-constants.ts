import * as path from 'path';

export const MAX_PROFILE_PICTURE_SIZE = 2 * 1024 * 1024;
export const VALID_UPLOADS_MIME_TYPES = ['image/jpeg', 'image/png'];
export const BASE_URL = 'https://staging.api-nestjs.boilerplate.hng.tech';
export const PROFILE_PHOTO_UPLOADS = path.join(__dirname, '..', 'uploads');

export const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:3000';
export const FRONTEND_RESET_PASSWORD = `${FRONTEND_URL}/reset-password`;
