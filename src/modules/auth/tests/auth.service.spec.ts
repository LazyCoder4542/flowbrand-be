import 'reflect-metadata';
import * as bcrypt from 'bcrypt';
import { HttpStatus } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { RedisService } from '@modules/redis/services/redis.service';
import QueueService from '@modules/email/queue.service';
import AuthenticationService from '../auth.service';
import { UserSession } from '../entities/user-session.entity';
import { FRONTEND_RESET_PASSWORD } from '@shared/constants/app-constants';
import { EmailService } from '@modules/email/email.service';
import { LockoutService } from '../lockout.service';
import { SessionService } from '../session.service';
import { AuthMetadata } from '../entities/auth-metadata.entity';
import { Response } from 'express';

describe('AuthenticationService', () => {
  let service: AuthenticationService;

  const userRepositoryMock = { findOne: jest.fn(), create: jest.fn(), save: jest.fn() };
  const jwtServiceMock = { sign: jest.fn() };
  const redisServiceMock = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    incr: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(false),
    expire: jest.fn().mockResolvedValue(undefined),
    delByPattern: jest.fn(),
  };
  const userSessionRepositoryMock = {
    create: jest.fn(),
    save: jest.fn(),
  };
  const queueServiceMock = {
    sendMail: jest.fn().mockResolvedValue({ jobId: 'mock-job' }),
  };
  const lockoutServiceMock = {
    findOrCreate: jest.fn(),
    isLocked: jest.fn(),
    secondsRemaining: jest.fn(),
    recordFailure: jest.fn(),
    clear: jest.fn(),
  };
  const sessionServiceMock = {
    create: jest.fn().mockResolvedValue({ rawToken: 'mock-refresh-token', sessionId: 'mock-session-id' }),
  };
  const authMetadataRepositoryMock = {
    create: jest.fn(),
    save: jest.fn(),
  };
  const queryRunnerMock = {
    connect: jest.fn().mockResolvedValue(undefined),
    startTransaction: jest.fn().mockResolvedValue(undefined),
    commitTransaction: jest.fn().mockResolvedValue(undefined),
    rollbackTransaction: jest.fn().mockResolvedValue(undefined),
    release: jest.fn().mockResolvedValue(undefined),
    manager: {
      create: jest.fn().mockImplementation((entity, data) => data),
      save: jest
        .fn()
        .mockResolvedValue({ id: 'user-1', email: 'jane@example.com', full_name: 'Jane Doe', avatar_url: null }),
      update: jest.fn().mockResolvedValue(undefined),
    },
  };
  const dataSourceMock = {
    createQueryRunner: jest.fn().mockReturnValue(queryRunnerMock),
  };
  const responseMock = {
    cookie: jest.fn(),
  };
  const emailServiceMock = {
    sendForgotPasswordMail: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthenticationService,
        { provide: getRepositoryToken(User), useValue: userRepositoryMock },
        { provide: getRepositoryToken(UserSession), useValue: userSessionRepositoryMock },
        { provide: getRepositoryToken(AuthMetadata), useValue: authMetadataRepositoryMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: RedisService, useValue: redisServiceMock },
        { provide: EmailService, useValue: emailServiceMock },
        { provide: DataSource, useValue: dataSourceMock },
        { provide: QueueService, useValue: queueServiceMock },
        { provide: LockoutService, useValue: lockoutServiceMock },
        { provide: SessionService, useValue: sessionServiceMock },
      ],
    }).compile();

    service = module.get<AuthenticationService>(AuthenticationService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // ─── createNewUser ────────────────────────────────────────────────────────

  describe('createNewUser', () => {
    const dto = {
      email: 'jane@example.com',
      full_name: 'Jane Doe',
      password: 'P@ssword123',
      country: 'Nigeria',
      terms_accepted: true,
    };

    it('creates a user and dispatches OTP email — no plaintext OTP in DB', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      userRepositoryMock.create.mockImplementation(input => input);
      userRepositoryMock.save.mockResolvedValueOnce({
        id: 'user-1',
        email: dto.email,
        full_name: dto.full_name,
        avatar_url: null,
      });
      jwtServiceMock.sign.mockReturnValueOnce('jwt');

      const result = await service.createNewUser(dto);

      expect(result.status_code).toBe(HttpStatus.CREATED);
      expect(result.message).toBe(SYS_MSG.USER_CREATED_SUCCESSFULLY);
      expect(result.data.user).toEqual({
        id: 'user-1',
        full_name: dto.full_name,
        email: dto.email,
        avatar_url: null,
      });

      // otp_code and expires_at must NOT be written to the DB
      const queryRunner = dataSourceMock.createQueryRunner();
      const created = queryRunner.manager.create.mock.calls[0][1];
      expect(created.auth_provider).toBe('email');
      expect(created.otp_code).toBeUndefined();
      expect(created.expires_at).toBeUndefined();

      // OTP hash must be stored in Redis
      expect(redisServiceMock.set).toHaveBeenCalledWith('otp:jane@example.com', expect.any(String), 300);

      // Email must be dispatched with a 6-digit OTP
      expect(queueServiceMock.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: 'register-otp',
          mail: expect.objectContaining({
            to: dto.email,
            context: expect.objectContaining({ otp: expect.stringMatching(/^\d{6}$/) }),
          }),
        })
      );
    });

    it('throws when a user with that email already exists', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'existing' });
      await expect(service.createNewUser(dto)).rejects.toThrow(CustomHttpException);
    });
  });

  // ─── loginUser ────────────────────────────────────────────────────────────

  describe('loginUser', () => {
    const metaMock = { id: 'meta-1', user_id: 'user-1', failed_attempts: 0, locked_until: null };

    it('returns an access token for valid credentials', async () => {
      const password = 'P@ssword123';
      const hashed = await bcrypt.hash(password, 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        full_name: 'Jane Doe',
        avatar_url: null,
        password: hashed,
      });
      lockoutServiceMock.findOrCreate.mockResolvedValueOnce(metaMock);
      lockoutServiceMock.isLocked.mockReturnValueOnce(false);
      lockoutServiceMock.clear.mockResolvedValueOnce(undefined);
      sessionServiceMock.create.mockResolvedValueOnce({ rawToken: 'raw-token', sessionId: 'session-1' });
      jwtServiceMock.sign.mockReturnValueOnce('jwt');

      const result = (await service.loginUser({ email: 'jane@example.com', password })) as Record<string, unknown>;

      expect(result.message).toBe(SYS_MSG.LOGIN_SUCCESSFUL);
      expect((result.data as Record<string, unknown>).access_token).toBe('jwt');
    });

    it('rejects unknown emails', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      await expect(service.loginUser({ email: 'x@y.z', password: 'pass' })).rejects.toThrow(CustomHttpException);
    });

    it('rejects bad passwords', async () => {
      const hashed = await bcrypt.hash('correct-password', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        password: hashed,
      });
      lockoutServiceMock.findOrCreate.mockResolvedValueOnce(metaMock);
      lockoutServiceMock.isLocked.mockReturnValueOnce(false);
      lockoutServiceMock.recordFailure.mockResolvedValueOnce(undefined);

      await expect(service.loginUser({ email: 'jane@example.com', password: 'wrong-password' })).rejects.toThrow(
        CustomHttpException
      );
    });

    it('rejects accounts without a stored password (OAuth-only)', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'user-1', email: 'jane@example.com', password: null });
      await expect(service.loginUser({ email: 'jane@example.com', password: 'anything' })).rejects.toThrow(
        CustomHttpException
      );
    });

    it('throws FORBIDDEN when the account is locked', async () => {
      const hashed = await bcrypt.hash('pass', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        password: hashed,
      });
      lockoutServiceMock.findOrCreate.mockResolvedValueOnce(metaMock);
      lockoutServiceMock.isLocked.mockReturnValueOnce(true);
      lockoutServiceMock.secondsRemaining.mockReturnValueOnce(300);

      await expect(service.loginUser({ email: 'jane@example.com', password: 'pass' })).rejects.toThrow(
        CustomHttpException
      );
    });
  });

  // ─── sendOtp ─────────────────────────────────────────────────────────────

  describe('sendOtp', () => {
    const user = { id: 'user-1', email: 'jane@example.com' };

    it('sends OTP and stores hash in Redis — no plaintext in DB', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });

      const result = await service.sendOtp('jane@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.OTP_SENT);
      expect(redisServiceMock.set).toHaveBeenCalledWith('otp:jane@example.com', expect.any(String), 300);
      expect(redisServiceMock.set).toHaveBeenCalledWith('limit:jane@example.com', '1', 30);
      expect(userRepositoryMock.save).not.toHaveBeenCalled();
      expect(queueServiceMock.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({ variant: 'register-otp', mail: expect.objectContaining({ to: 'jane@example.com' }) })
      );
    });

    it('returns 200 silently for unknown emails — prevents enumeration', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);

      const result = await service.sendOtp('nobody@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(queueServiceMock.sendMail).not.toHaveBeenCalled();
    });

    it('throws 429 when cooldown key exists', async () => {
      redisServiceMock.exists.mockResolvedValueOnce(true);
      await expect(service.sendOtp('jane@example.com')).rejects.toThrow(CustomHttpException);
    });
  });

  // ─── verifyOtp ────────────────────────────────────────────────────────────

  describe('verifyOtp', () => {
    const user = { id: 'user-1', email: 'jane@example.com', full_name: 'Jane', avatar_url: null, is_verified: false };

    it('verifies a valid OTP, marks user verified, clears Redis keys and DB OTP fields', async () => {
      const otp = '123456';
      const hashedOtp = await bcrypt.hash(otp, 10);

      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });
      redisServiceMock.get.mockResolvedValueOnce(hashedOtp);
      redisServiceMock.incr.mockResolvedValueOnce(1);
      userRepositoryMock.save.mockResolvedValueOnce(undefined);
      jwtServiceMock.sign.mockReturnValueOnce('jwt');

      const result = await service.verifyOtp('jane@example.com', otp);

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.EMAIL_VERIFIED);

      // DB otp_code and expires_at must be cleared
      const saved = userRepositoryMock.save.mock.calls[0][0];
      expect(saved.otp_code).toBeNull();
      expect(saved.expires_at).toBeNull();
      expect(saved.is_verified).toBe(true);

      expect(redisServiceMock.del).toHaveBeenCalledWith('otp:jane@example.com');
      expect(redisServiceMock.del).toHaveBeenCalledWith('attempts:jane@example.com');
      expect(redisServiceMock.del).toHaveBeenCalledWith('limit:jane@example.com');
    });

    it('throws 400 for unknown email — same shape as bad OTP, prevents enumeration', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      await expect(service.verifyOtp('nobody@example.com', '123456')).rejects.toThrow(CustomHttpException);
    });

    it('throws 400 when OTP has expired before burning an attempt', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });
      redisServiceMock.get.mockResolvedValueOnce(null); // OTP missing/expired

      await expect(service.verifyOtp('jane@example.com', '123456')).rejects.toThrow(CustomHttpException);
      expect(redisServiceMock.incr).not.toHaveBeenCalled(); // no attempt burned
    });

    it('throws 429 when attempt count exceeds limit', async () => {
      const hashedOtp = await bcrypt.hash('123456', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });
      redisServiceMock.get.mockResolvedValueOnce(hashedOtp);
      redisServiceMock.incr.mockResolvedValueOnce(6);

      await expect(service.verifyOtp('jane@example.com', '123456')).rejects.toThrow(CustomHttpException);
    });

    it('throws 400 when OTP does not match', async () => {
      const hashedOtp = await bcrypt.hash('654321', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });
      redisServiceMock.get.mockResolvedValueOnce(hashedOtp);
      redisServiceMock.incr.mockResolvedValueOnce(1);

      await expect(service.verifyOtp('jane@example.com', '999999')).rejects.toThrow(CustomHttpException);
    });

    it('uses expire (not set) for atomic TTL on first attempt', async () => {
      const hashedOtp = await bcrypt.hash('123456', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });
      redisServiceMock.get.mockResolvedValueOnce(hashedOtp);
      redisServiceMock.incr.mockResolvedValueOnce(1);
      jwtServiceMock.sign.mockReturnValueOnce('jwt');
      userRepositoryMock.save.mockResolvedValueOnce(undefined);

      await service.verifyOtp('jane@example.com', '123456');

      expect(redisServiceMock.expire).toHaveBeenCalledWith('attempts:jane@example.com', 300);
      expect(redisServiceMock.set).not.toHaveBeenCalledWith(
        'attempts:jane@example.com',
        expect.anything(),
        expect.anything()
      );
    });
  });

  // ─── resendOtp ────────────────────────────────────────────────────────────

  describe('resendOtp', () => {
    const user = { id: 'user-1', email: 'jane@example.com' };

    it('clears old OTP and attempts then issues a fresh code', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ ...user });

      const result = await service.resendOtp('jane@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(redisServiceMock.del).toHaveBeenCalledWith('otp:jane@example.com');
      expect(redisServiceMock.del).toHaveBeenCalledWith('attempts:jane@example.com');
      expect(queueServiceMock.sendMail).toHaveBeenCalled();
    });

    it('throws 429 when cooldown key exists — does not clear existing OTP', async () => {
      redisServiceMock.exists.mockResolvedValueOnce(true);

      await expect(service.resendOtp('jane@example.com')).rejects.toThrow(CustomHttpException);
      expect(redisServiceMock.del).not.toHaveBeenCalled();
      expect(queueServiceMock.sendMail).not.toHaveBeenCalled();
    });
  });

  // ─── changePassword ───────────────────────────────────────────────────────

  describe('changePassword', () => {
    it('updates the password when the old one matches', async () => {
      const oldPassword = 'OldP@ss123';
      const hashed = await bcrypt.hash(oldPassword, 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'user-1', password: hashed });
      userRepositoryMock.save.mockResolvedValueOnce(undefined);

      const result = await service.changePassword('user-1', oldPassword, 'NewP@ss123');

      expect(result.message).toBe(SYS_MSG.PASSWORD_UPDATED);
      expect(userRepositoryMock.save).toHaveBeenCalled();
    });

    it('throws when the user is missing', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      await expect(service.changePassword('user-1', 'x', 'y')).rejects.toThrow(CustomHttpException);
    });

    it('throws when the old password is wrong', async () => {
      const hashed = await bcrypt.hash('correct-old', 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'user-1', password: hashed });
      await expect(service.changePassword('user-1', 'wrong-old', 'new')).rejects.toThrow(CustomHttpException);
    });
  });

  describe('forgotPassword', () => {
    it('stores an OTP in Redis and returns success for a known email', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        full_name: 'Jane Doe',
      });

      const result = await service.forgotPassword('jane@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.FORGOT_PASSWORD_OTP_SENT);
      expect(redisServiceMock.set).toHaveBeenCalledWith(
        expect.stringContaining('jane@example.com'),
        expect.stringMatching(/^\d{6}$/),
        300
      );
      expect(emailServiceMock.sendForgotPasswordMail).toHaveBeenCalledWith(
        'jane@example.com',
        'Jane Doe',
        FRONTEND_RESET_PASSWORD,
        expect.stringMatching(/^\d{6}$/)
      );
    });

    it('still returns success when OTP issuance fails (enumeration-safe)', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        full_name: 'Jane Doe',
      });
      redisServiceMock.set.mockRejectedValueOnce(new Error('redis down'));

      const result = await service.forgotPassword('jane@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.FORGOT_PASSWORD_OTP_SENT);
    });

    it('returns the same success response for an unknown email without touching Redis', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);

      const result = await service.forgotPassword('nobody@example.com');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.FORGOT_PASSWORD_OTP_SENT);
      expect(redisServiceMock.set).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const email = 'jane@example.com';
    const otp = '123456';
    const key = `reset_otp:${email}`;

    it('resets the password and revokes all sessions for a valid OTP', async () => {
      redisServiceMock.get.mockResolvedValueOnce(otp);
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'user-1', email, password: 'old-hash' });
      const result = await service.resetPassword(email, otp, 'NewP@ss123');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.PASSWORD_UPDATED);
      expect(queryRunnerMock.commitTransaction).toHaveBeenCalled();
      expect(queryRunnerMock.manager.update).toHaveBeenCalledWith(
        User,
        { id: 'user-1' },
        { password: expect.any(String) }
      );
      expect(queryRunnerMock.manager.update).toHaveBeenCalledWith(
        UserSession,
        { user_id: 'user-1', is_revoked: false },
        { is_revoked: true, revoked_at: expect.any(Date) }
      );
      expect(redisServiceMock.delByPattern).toHaveBeenCalledWith('active_session:user-1:*');
      expect(redisServiceMock.del).toHaveBeenCalledWith(key);
    });

    it('throws for an invalid or expired OTP', async () => {
      redisServiceMock.get.mockResolvedValueOnce(null);

      await expect(service.resetPassword(email, 'wrong', 'NewP@ss123')).rejects.toThrow(CustomHttpException);
      expect(userRepositoryMock.findOne).not.toHaveBeenCalled();
      expect(userRepositoryMock.save).not.toHaveBeenCalled();
    });

    it('throws for an OTP mismatch', async () => {
      redisServiceMock.get.mockResolvedValueOnce('654321');

      await expect(service.resetPassword(email, otp, 'NewP@ss123')).rejects.toThrow(CustomHttpException);
      expect(userRepositoryMock.findOne).not.toHaveBeenCalled();
      expect(userRepositoryMock.save).not.toHaveBeenCalled();
    });

    it('deletes the OTP key and throws when OTP is valid but user no longer exists', async () => {
      redisServiceMock.get.mockResolvedValueOnce(otp);
      userRepositoryMock.findOne.mockResolvedValueOnce(null);

      await expect(service.resetPassword(email, otp, 'NewP@ss123')).rejects.toThrow(CustomHttpException);
      expect(redisServiceMock.del).toHaveBeenCalledWith(key);
      expect(userRepositoryMock.save).not.toHaveBeenCalled();
    });
  });
});
