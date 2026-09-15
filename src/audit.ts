import { randomUUID } from 'crypto';
import { run, rows, AuditEvent } from './database.js';

type AuditInput = {
  userId?: string;
  event: string;
  app?: string;
  result: 'success' | 'failure';
  redirectUri?: string;
};

export async function recordAudit(input: AuditInput) {
  try {
    await run('INSERT INTO auth_audit_event (id, user_id, event, app, result, timestamp, redirect_uri) VALUES (?, ?, ?, ?, ?, ?, ?)', [randomUUID(), input.userId || '', input.event, input.app || 'auth', input.result, new Date().toISOString(), input.redirectUri || '']);
  } catch (error) {
    console.error('Could not write audit event', error);
  }
}

export async function getAuditEvents(userId: string) {
  const events = await rows<AuditEvent>('auth_audit_event', 'user_id = ?', [userId]);
  return events
    .map(({ event, app, result, timestamp, redirectUri }) => ({ event, app, result, timestamp, redirectUri }))
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp));
}
