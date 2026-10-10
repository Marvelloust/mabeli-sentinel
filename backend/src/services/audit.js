import { AuditLog } from '../models/index.js';

export async function audit(req, action, entityType, entityId, details = {}) {
  try {
    await AuditLog.create({
      organization: req.organization?._id,
      user: req.user?._id,
      action,
      entityType,
      entityId: entityId ? String(entityId) : undefined,
      details,
      ip: req.ip
    });
  } catch (error) {
    console.error('Audit write failed:', error.message);
  }
}
