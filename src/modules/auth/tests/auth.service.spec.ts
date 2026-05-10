import 'reflect-metadata';
import * as bcrypt from 'bcrypt';
import { HttpStatus } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import AuthenticationService from '../auth.service';
import { RedisService } from '@modules/redis/services/redis.service';
import { EmailService } from '@modules/email/email.service';
import { UserSession } from '../entities/user-session.entity';

describe('AuthenticationService', () => {
  let service: AuthenticationService;
  const userRepositoryMock = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
  };
  const userSessionRepositoryMock = {
    update: jest.fn(),
  };
  const jwtServiceMock = {
    sign: jest.fn(),
  };
  const redisServiceMock = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    incr: jest.fn(),
    delByPattern: jest.fn(),
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
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: RedisService, useValue: redisServiceMock },
        { provide: EmailService, useValue: emailServiceMock },
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

  describe('createNewUser', () => {
    const dto = {
      email: 'jane@example.com',
      full_name: 'Jane Doe',
      password: 'P@ssword123',
      country: 'Nigeria',
    };

    it('creates a user when none exists with that email', async () => {
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
      expect(result.access_token).toBe('jwt');
      expect(result.data.user).toEqual({
        id: 'user-1',
        full_name: dto.full_name,
        email: dto.email,
        avatar_url: null,
      });
      const created = userRepositoryMock.create.mock.calls[0][0];
      expect(created.auth_provider).toBe('email');
      expect(created.otp_code).toMatch(/^\d{6}$/);
      expect(created.expires_at).toBeInstanceOf(Date);
    });

    it('throws when a user with that email already exists', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'existing' });
      await expect(service.createNewUser(dto)).rejects.toThrow(CustomHttpException);
    });
  });

  describe('loginUser', () => {
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
      jwtServiceMock.sign.mockReturnValueOnce('jwt');

      const result = await service.loginUser({ email: 'jane@example.com', password });

      expect(result.message).toBe(SYS_MSG.LOGIN_SUCCESSFUL);
      expect(result.access_token).toBe('jwt');
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
        full_name: 'Jane Doe',
        avatar_url: null,
        password: hashed,
      });
      await expect(service.loginUser({ email: 'jane@example.com', password: 'wrong-password' })).rejects.toThrow(
        CustomHttpException
      );
    });

    it('rejects accounts without a stored password (OAuth-only)', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        password: null,
      });
      await expect(service.loginUser({ email: 'jane@example.com', password: 'anything' })).rejects.toThrow(
        CustomHttpException
      );
    });
  });

  describe('changePassword', () => {
    it('updates the password when the old one matches', async () => {
      const oldPassword = 'OldP@ss123';
      const newPassword = 'NewP@ss123';
      const hashed = await bcrypt.hash(oldPassword, 10);
      userRepositoryMock.findOne.mockResolvedValueOnce({ id: 'user-1', password: hashed });
      userRepositoryMock.save.mockResolvedValueOnce(undefined);

      const result = await service.changePassword('user-1', oldPassword, newPassword);

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
        expect.stringContaining('jane@example.com'),
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
      userRepositoryMock.save.mockResolvedValueOnce(undefined);
      redisServiceMock.del.mockResolvedValueOnce(undefined);
      redisServiceMock.delByPattern.mockResolvedValueOnce(undefined);
      userSessionRepositoryMock.update.mockResolvedValueOnce(undefined);

      const result = await service.resetPassword(email, otp, 'NewP@ss123');

      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.message).toBe(SYS_MSG.PASSWORD_UPDATED);
      expect(userRepositoryMock.save).toHaveBeenCalled();
      expect(redisServiceMock.del).toHaveBeenCalledWith(key);
      expect(redisServiceMock.delByPattern).toHaveBeenCalledWith('active_session:user-1:*');
      expect(userSessionRepositoryMock.update).toHaveBeenCalledWith(
        { user_id: 'user-1', is_revoked: false },
        { is_revoked: true, revoked_at: expect.any(Date) }
      );
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
