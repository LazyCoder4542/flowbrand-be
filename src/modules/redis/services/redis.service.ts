import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import Redis, { RedisOptions } from 'ioredis';
import authConfig from '@config/auth.config';
import * as SYS_MSG from '@shared/constants/SystemMessages';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: Redis;
  private readonly logger = new Logger(RedisService.name);

  onModuleInit() {
    const { host, port, password, username } = authConfig().redis;

    const options: RedisOptions = {
      host,
      port: port ? Number(port) : 6379,
      ...(password && { password }),
      ...(username && { username }),
      connectTimeout: 5000, // 5secs
      lazyConnect: true,
      enableOfflineQueue: false,
      retryStrategy: (times: number) => {
        if (times > 5) {
          this.logger.error(SYS_MSG.REDIS_MESSAGES.RETRY_LIMIT_REACHED);
          return null;
        }
        const delay = Math.min(times * 200, 2000); // 2s max delay
        this.logger.warn(SYS_MSG.REDIS_MESSAGES.RECONNECT_ATTEMPT(times, delay));
        return delay;
      },
    };

    this.client = new Redis(options);

    this.client.on('connect', () => this.logger.log('Redis connection established'));
    this.client.on('ready', () => this.logger.log('Redis client ready'));
    this.client.on('close', () => this.logger.warn('Redis connection closed'));
    this.client.on('error', (err: Error) => {
      if (err.message.includes('OOM')) {
        this.logger.error(SYS_MSG.REDIS_MESSAGES.CRITICAL_OOM, err.message);
      } else {
        this.logger.error(SYS_MSG.REDIS_MESSAGES.CLIENT_ERROR, err.message);
      }
    });

    this.client.connect().catch(err => {
      this.logger.error(SYS_MSG.REDIS_MESSAGES.INITIAL_CONNECTION_FAILED, err.message);
    });
  }

  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key);
    } catch (err) {
      this.logger.error(`GET failed`, (err as Error).message);
      return null;
    }
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    try {
      if (ttl) {
        await this.client.set(key, value, 'EX', ttl);
      } else {
        await this.client.set(key, value);
      }
    } catch (err) {
      this.logger.error(`SET failed`, (err as Error).message);
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (err) {
      this.logger.error(`DEL failed`, (err as Error).message);
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      return (await this.client.exists(key)) === 1;
    } catch (err) {
      this.logger.error(`EXISTS failed`, (err as Error).message);
      return false;
    }
  }

  async incr(key: string): Promise<number | null> {
    try {
      return await this.client.incr(key);
    } catch (err) {
      this.logger.error(`INCR failed`, (err as Error).message);
      return null;
    }
  }

  async expire(key: string, ttl: number): Promise<void> {
    try {
      await this.client.expire(key, ttl);
    } catch (err) {
      this.logger.error(`EXPIRE failed`, (err as Error).message);
    }
  }

  async delByPattern(pattern: string): Promise<void> {
    try {
      let cursor = '0';
      const keysToDelete: string[] = [];

      do {
        const [nextCursor, keys] = await this.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = nextCursor;
        keysToDelete.push(...keys);
      } while (cursor !== '0');

      if (keysToDelete.length > 0) {
        await this.client.del(...keysToDelete);
        this.logger.log(SYS_MSG.REDIS_MESSAGES.PATTERN_DELETE_SUCCESS(keysToDelete.length, pattern));
      }
    } catch (err) {
      this.logger.error(`delByPattern failed`, (err as Error).message);
    }
  }

  async onModuleDestroy() {
    await this.client?.quit();
    this.logger.log(SYS_MSG.REDIS_MESSAGES.CONNECTION_CLOSED);
  }
}
