import { Test, TestingModule } from '@nestjs/testing';
import { getQueueToken } from '@nestjs/bull';
import QueueService from './queue.service';

describe('QueueService', () => {
  let service: QueueService;
  const queueMock = {
    add: jest.fn().mockResolvedValue({ id: 'job-1' }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        QueueService,
        {
          provide: getQueueToken('emailSending'),
          useValue: queueMock,
        },
      ],
    }).compile();

    service = module.get<QueueService>(QueueService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('adds email jobs with retry and backoff configuration', async () => {
    const result = await service.sendMail({
      variant: 'register-otp',
      mail: {
        to: 'user@example.com',
        context: { otp: '123456', email: 'user@example.com' },
      },
    });

    expect(queueMock.add).toHaveBeenCalledWith(
      'register-otp',
      expect.objectContaining({
        mail: expect.objectContaining({
          to: 'user@example.com',
        }),
      }),
      {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
      }
    );
    expect(result).toEqual({ jobId: 'job-1' });
  });
});
