import { Request } from 'express';
import { pool } from '../db/pool';

export interface AuditEventParams {
  userId?: string | null;
  eventType: string;
  req?: Request;
  details?: Record<string, unknown>;
}

export async function logAuditEvent({
  userId = null,
  eventType,
  req,
  details = {},
}: AuditEventParams): Promise<void> {
  try {
    let ip = null;
    let userAgent = null;

    if (req) {
      ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || null;
      userAgent = req.headers['user-agent'] || null;
    }

    await pool.query(
      `INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, eventType, ip, userAgent, JSON.stringify(details)]
    );
  } catch (err) {
    // Non-fatal: do not block primary request if audit log insert fails
    console.error('[AuditLog] Failed to insert audit log entry:', err);
  }
}
