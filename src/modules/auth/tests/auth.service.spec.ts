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
import { UserSession } from '../entities/user-session.entity';
import { RedisService } from '@modules/redis/services/redis.service';

describe('AuthenticationService', () => {
  let service: AuthenticationService;
  // Ensure jwt refresh secret is set for hashing in tests
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-secret';
  const userRepositoryMock = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    manager: {
      transaction: jest.fn(),
    },
  };
  const jwtServiceMock = {
    sign: jest.fn(),
  };
  const userSessionRepositoryMock = {
    create: jest.fn(),
    save: jest.fn(),
  };
  const redisServiceMock = {
    set: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
  };
import { LockoutService } from '../lockout.service';
import { SessionService } from '../session.service';

describe('AuthenticationService', () => {
  let service: AuthenticationService;

  const userRepositoryMock = { findOne: jest.fn(), create: jest.fn(), save: jest.fn() };
  const jwtServiceMock = { sign: jest.fn() };
  const lockoutServiceMock = {
    findOrCreate: jest.fn(),
    isLocked: jest.fn(),
    secondsRemaining: jest.fn(),
    recordFailure: jest.fn(),
    clear: jest.fn(),
  };
  const sessionServiceMock = { create: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthenticationService,
        { provide: getRepositoryToken(User), useValue: userRepositoryMock },
        { provide: getRepositoryToken(UserSession), useValue: userSessionRepositoryMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: RedisService, useValue: redisServiceMock },
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
        full_name: 'Jane Doe',
        avatar_url: null,
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
      userRepositoryMock.findOne.mockResolvedValueOnce({
        id: 'user-1',
        email: 'jane@example.com',
        password: null,
      });
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

  describe('handleOAuthLogin', () => {
    const googleProfile = {
      provider: 'google',
      providerId: 'google-123',
      email: 'user@example.com',
      full_name: 'John Doe',
      avatar_url: 'https://example.com/avatar.jpg',
    };
    beforeEach(() => {
      // Setup manager.transaction to return the callback result
      (userRepositoryMock.manager.transaction as jest.Mock).mockImplementation(callback =>
        callback({
          getRepository: jest.fn(() => ({
            findOne: userRepositoryMock.findOne,
            create: userRepositoryMock.create,
            save: userRepositoryMock.save,
          })),
        })
      );
    });

    it('creates a new user when email does not exist', async () => {
      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      userRepositoryMock.create.mockImplementation(input => input);
      userRepositoryMock.save.mockResolvedValueOnce({
        id: 'new-user-1',
        email: googleProfile.email,
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      });
      userRepositoryMock.save.mockResolvedValueOnce({
        id: 'new-user-1',
        email: googleProfile.email,
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      });
      userSessionRepositoryMock.create.mockImplementation(input => input);
      userSessionRepositoryMock.save.mockResolvedValueOnce({
        id: 'session-1',
        user_id: 'new-user-1',
        refresh_token: 'hashed-token',
      });
      jwtServiceMock.sign.mockReturnValueOnce('access-jwt');

      const result = await service.handleOAuthLogin(googleProfile);

      // Verify new user was created with OAuth data
      const createdUser = userRepositoryMock.create.mock.calls[0][0];
      expect(createdUser.email).toBe(googleProfile.email);
      expect(createdUser.full_name).toBe(googleProfile.full_name);
      expect(createdUser.avatar_url).toBe(googleProfile.avatar_url);
      expect(createdUser.auth_provider).toBe('google');
      expect(createdUser.provider_user_id).toBe(googleProfile.providerId);
      expect(createdUser.password).toBeNull();

      // Verify session was created
      expect(userSessionRepositoryMock.create).toHaveBeenCalled();
      expect(userSessionRepositoryMock.save).toHaveBeenCalled();

      // Verify response
      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.access_token).toBe('access-jwt');
      expect(result.refresh_token).toBeDefined();
      expect(result.data.user.email).toBe(googleProfile.email);
    });

    it('links OAuth provider to existing email user', async () => {
      const existingUser = {
        id: 'existing-user-1',
        email: googleProfile.email,
        auth_provider: 'email',
        provider_user_id: null,
        full_name: 'John Old',
        avatar_url: null,
      };

      userRepositoryMock.findOne.mockResolvedValueOnce(existingUser);
      userRepositoryMock.save.mockResolvedValueOnce({
        ...existingUser,
        auth_provider: 'google',
        provider_user_id: googleProfile.providerId,
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      });
      userSessionRepositoryMock.create.mockImplementation(input => input);
      userSessionRepositoryMock.save.mockResolvedValueOnce({
        id: 'session-2',
        user_id: 'existing-user-1',
        refresh_token: 'hashed-token',
      });
      jwtServiceMock.sign.mockReturnValueOnce('access-jwt');

      const result = await service.handleOAuthLogin(googleProfile);

      // Verify provider was linked
      const updatedUser = userRepositoryMock.save.mock.calls[0][0];
      expect(updatedUser.auth_provider).toBe('google');
      expect(updatedUser.provider_user_id).toBe(googleProfile.providerId);

      // Verify response
      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.data.user.id).toBe('existing-user-1');
    });

    it('throws conflict when same email has different Google provider ID', async () => {
      const existingUser = {
        id: 'google-user-1',
        email: googleProfile.email,
        auth_provider: 'google',
        provider_user_id: 'different-google-id',
        full_name: 'John Doe',
      };

      userRepositoryMock.findOne.mockResolvedValueOnce(existingUser);

      await expect(service.handleOAuthLogin(googleProfile)).rejects.toThrow(CustomHttpException);
    });

    it('persists session and returns tokens', async () => {
      const user = {
        id: 'user-1',
        email: googleProfile.email,
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      };

      userRepositoryMock.findOne.mockResolvedValueOnce(user);
      userRepositoryMock.save.mockResolvedValueOnce(user);
      userSessionRepositoryMock.create.mockImplementation(input => input);
      userSessionRepositoryMock.save.mockResolvedValueOnce({
        id: 'session-1',
        user_id: 'user-1',
        refresh_token: 'hashed-token',
      });
      jwtServiceMock.sign.mockReturnValueOnce('access-jwt');

      const result = await service.handleOAuthLogin(googleProfile);

      // Verify session was created with hashed token (not plaintext)
      const sessionPayload = userSessionRepositoryMock.create.mock.calls[0][0];
      expect(sessionPayload.refresh_token).toBeDefined();
      // The hash should be different from a simple UUID
      expect(sessionPayload.refresh_token).toMatch(/^[a-f0-9]{64}$/); // SHA256 hex format

      // Verify JWT was signed
      expect(jwtServiceMock.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'user-1',
          email: googleProfile.email,
        })
      );

      // Verify plaintext token returned to client
      expect(result.refresh_token).toBeDefined();
      expect(result.refresh_token).not.toBe(sessionPayload.refresh_token);
      expect(result.access_token).toBe('access-jwt');
    });

    it('does not block login when Redis fails', async () => {
      const user = {
        id: 'user-1',
        email: googleProfile.email,
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      };
      userRepositoryMock.findOne.mockResolvedValueOnce(user);
      userRepositoryMock.save.mockResolvedValueOnce(user);
      userSessionRepositoryMock.create.mockImplementation(input => input);
      userSessionRepositoryMock.save.mockResolvedValueOnce({
        id: 'session-1',
        user_id: 'user-1',
        refresh_token: 'hashed-token',
      });
      jwtServiceMock.sign.mockReturnValueOnce('access-jwt');
      // Make Redis actually fail so we assert handleOAuthLogin is resilient.
      redisServiceMock.set.mockRejectedValueOnce(new Error('redis down'));
      const originalConsoleError = console.error;
      console.error = jest.fn();
      const result = await service.handleOAuthLogin(googleProfile);
      // Verify login succeeds despite Redis error
      expect(result.status_code).toBe(HttpStatus.OK);
      expect(result.access_token).toBe('access-jwt');
      expect(result.refresh_token).toBeDefined();
      console.error = originalConsoleError;
    });

    it('rejects OAuth profile with missing email', async () => {
      const profileWithoutEmail = {
        ...googleProfile,
        email: '',
      };

      await expect(service.handleOAuthLogin(profileWithoutEmail)).rejects.toThrow(CustomHttpException);
    });

    it('normalizes email to lowercase', async () => {
      const profileWithUpperEmail = {
        ...googleProfile,
        email: 'USER@EXAMPLE.COM',
      };

      userRepositoryMock.findOne.mockResolvedValueOnce(null);
      userRepositoryMock.create.mockImplementation(input => input);
      userRepositoryMock.save.mockResolvedValueOnce({
        id: 'user-1',
        email: 'user@example.com',
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      });
      userRepositoryMock.save.mockResolvedValueOnce({
        id: 'user-1',
        email: 'user@example.com',
        full_name: googleProfile.full_name,
        avatar_url: googleProfile.avatar_url,
      });
      userSessionRepositoryMock.create.mockImplementation(input => input);
      userSessionRepositoryMock.save.mockResolvedValueOnce({
        id: 'session-1',
        user_id: 'user-1',
        refresh_token: 'hashed-token',
      });
      jwtServiceMock.sign.mockReturnValueOnce('access-jwt');

      await service.handleOAuthLogin(profileWithUpperEmail);

      // Verify email was normalized in queries and creation
      expect(userRepositoryMock.findOne).toHaveBeenCalledWith(
        expect.objectContaining({ where: { email: 'user@example.com' } })
      );
      const createdUser = userRepositoryMock.create.mock.calls[0][0];
      expect(createdUser.email).toBe('user@example.com');
    });
  });
});
}
