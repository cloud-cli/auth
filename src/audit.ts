import { randomUUID } from 'crypto';
import { all, run, rows, AuditEvent } from './database.js';

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

export async function getAuditEvents(userId: string, options: { app?: string; event?: string; limit?: number; offset?: number } = {}) {
  const clauses = ['user_id = ?'];
  const params: unknown[] = [userId];
  if (options.app) { clauses.push('app = ?'); params.push(options.app); }
  if (options.event) { clauses.push('event = ?'); params.push(options.event); }
  const limit = Math.min(Math.max(options.limit || 50, 1), 50);
  const offset = Math.max(options.offset || 0, 0);
  const where = clauses.join(' AND ');
  const events = await rows<AuditEvent>('auth_audit_event', `${where} ORDER BY timestamp DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
  const total = await all<{ count: number }>(`SELECT COUNT(*) AS count FROM auth_audit_event WHERE ${where}`, params);
  return { items: events.map(({ event, app, result, timestamp, redirectUri }) => ({ event, app, result, timestamp, redirectUri })), total: total[0]?.count || 0, limit, offset };
}

export async function getAuditOptions(userId: string) {
  const values = await all<{ app: string; event: string }>('SELECT DISTINCT app, event FROM auth_audit_event WHERE user_id = ?', [userId]);
  return { apps: [...new Set(values.map((value) => value.app))].sort(), events: [...new Set(values.map((value) => value.event))].sort() };
}
