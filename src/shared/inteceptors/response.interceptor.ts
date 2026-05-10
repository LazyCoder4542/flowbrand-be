import {
  CallHandler,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ResponseInterceptor.name);
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      map((res: any) => this.responseHandler(res, context)),
      catchError((err: unknown) => throwError(() => this.errorHandler(err, context)))
    );
  }

  errorHandler(exception: unknown, context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    if (exception instanceof HttpException) return exception;
    this.logger.error(
      `Error processing request for ${req.method} ${req.url}, Message: ${exception['message']}, Stack: ${exception['stack']}`
    );
    return new InternalServerErrorException({
      status_code: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error',
    });
  }

  responseHandler(res: any, context: ExecutionContext) {
    const ctx = context.switchToHttp();
    const response = ctx.getResponse();
    const status_code = response.statusCode;
    response.setHeader('Content-Type', 'application/json');
    if (typeof res === 'object') {
      const { message, ...data } = res;
      const req = ctx.getRequest();

      // Redact sensitive fields before logging
      const safeData = { ...data };
      if (safeData && (safeData.access_token || safeData.refresh_token || safeData.token)) {
        if (safeData.access_token) safeData.access_token = '[REDACTED]';
        if (safeData.refresh_token) safeData.refresh_token = '[REDACTED]';
        if (safeData.token) safeData.token = '[REDACTED]';
      }

      this.logger.debug(
        `Response for ${req.method} ${req.url}: ${JSON.stringify({ message, ...safeData })}`,
      );

      return {
        status_code,
        message,
        ...data,
      };
    }

    return res;
  }
}
