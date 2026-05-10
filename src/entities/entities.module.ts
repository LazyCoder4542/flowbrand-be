import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@modules/user/entities/user.entity';
import { UserRole } from '@modules/user/entities/user-role.entity';
import { AuthMetadata } from '@modules/auth/entities/auth-metadata.entity';
import { UserSession } from '@modules/auth/entities/user-session.entity';
import { ApiHealth } from '@modules/api-status/entities/api-status.entity';
import { Request as RequestEntity } from '@modules/api-status/entities/request.entity';
import { WeeklyLog } from '@modules/weekly-logs/entities/weekly-log.entity';
import { Notification } from '@modules/notifications/entities/notifications.entity';
import { AdminNotification } from '@modules/notifications/entities/admin-notification.entity';
import { NotificationPreference } from '@modules/notifications/entities/notification-preference.entity';
import { Subscription } from '@modules/subscriptions/entities/subscription.entity';
import { FunnelStage } from '@modules/funnels/entities/funnel-stage.entity';
import { FunnelTask } from '@modules/funnels/entities/funnel-task.entity';
import { UploadedDocument } from '@modules/uploaded-documents/entities/uploaded-document.entity';
import { Strategy } from '@modules/strategies/entities/strategy.entity';
import { StrategyDocument } from '@modules/strategies/entities/strategy-document.entity';
import { TokenUsage } from '@modules/strategies/entities/token-usage.entity';
import { Waitlist } from '@modules/waitlist/entities/waitlist.entity';

const entities = [
  User,
  UserRole,
  AuthMetadata,
  UserSession,
  ApiHealth,
  RequestEntity,
  WeeklyLog,
  Notification,
  AdminNotification,
  NotificationPreference,
  Subscription,
  FunnelStage,
  FunnelTask,
  UploadedDocument,
  Strategy,
  StrategyDocument,
  TokenUsage,
  Waitlist,
];

@Global()
@Module({
  imports: [TypeOrmModule.forFeature(entities)],
  exports: [TypeOrmModule],
})
export class AllEntitiesModule {}
