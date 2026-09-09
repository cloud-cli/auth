import { randomUUID } from 'crypto';
import { Query, Resource } from '@cloud-cli/store';
import { AuditEvent } from './store.js';

type AuditInput = {
  userId?: string;
  event: string;
  app?: string;
  result: 'success' | 'failure';
  redirectUri?: string;
};

export async function recordAudit(input: AuditInput) {
  try {
    await new AuditEvent({
      id: randomUUID(),
      userId: input.userId || '',
      event: input.event,
      app: input.app || 'auth',
      result: input.result,
      timestamp: new Date().toISOString(),
      redirectUri: input.redirectUri || '',
    }).save();
  } catch (error) {
    console.error('Could not write audit event', error);
  }
}

export async function getAuditEvents(userId: string) {
  const events = await Resource.find(AuditEvent, new Query<AuditEvent>().where('userId').is(userId));
  return events
    .map(({ event, app, result, timestamp, redirectUri }) => ({ event, app, result, timestamp, redirectUri }))
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp));
}
