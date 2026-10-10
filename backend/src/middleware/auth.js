import jwt from 'jsonwebtoken';
import { Membership, Organization, Setting, User, TrafficEvent, Detection, Alert, Incident, Integration, AuditLog, BenchmarkRun } from '../models/index.js';
import { tenantStorage } from '../services/tenant-context.js';

export async function migrateLegacyUser(user) {
  const existingMembership = await Membership.findOne({ user: user._id, status: 'active' }).populate('organization');
  if (existingMembership) return;

  let org = await Organization.findOne({ slug: 'legacy-mabeli-workspace' });
  if (!org) {
    const setting = await Setting.findOne({ key: 'global' }).setOptions({ bypassTenant: true }).lean().catch(() => null);
    org = await Organization.create({
      name: setting?.organizationName || 'Mabeli Technology Workspace',
      slug: 'legacy-mabeli-workspace',
      createdBy: user._id,
      onboardingCompletedAt: new Date()
    });
    const orgId = org._id;
    await Promise.all([
      TrafficEvent.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      Detection.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      Alert.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      Incident.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      Integration.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      AuditLog.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true }),
      BenchmarkRun.updateMany({ $or: [{ organization: { $exists: false } }, { organization: null }] }, { $set: { organization: orgId } }).setOptions({ bypassTenant: true })
    ]).catch(() => {});
  }

  const legacyUsers = await User.find({ active: true }).lean();
  for (const legacy of legacyUsers) {
    await Membership.findOneAndUpdate(
      { user: legacy._id, organization: org._id },
      { $setOnInsert: { user: legacy._id, organization: org._id, role: legacy.role === 'admin' ? 'admin' : 'analyst', status: 'active', invitedBy: user._id } },
      { upsert: true }
    );
  }
}

export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Authentication required' });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub).select('-passwordHash');
    if (!user || !user.active) return res.status(401).json({ message: 'Account unavailable' });

    await migrateLegacyUser(user);
    const memberships = await Membership.find({ user: user._id, status: 'active' }).populate('organization').lean();
    if (!memberships.length) return res.status(403).json({ message: 'Your account does not belong to an active organization workspace' });

    const requestedOrgId = req.headers['x-organization-id'] || req.query.organizationId;
    const membership = memberships.find(m => String(m.organization?._id || m.organization) === String(requestedOrgId || '')) || memberships[0];
    const organization = membership.organization;
    if (!organization?.active) return res.status(403).json({ message: 'Organization workspace is unavailable' });

    req.user = user;
    req.membership = membership;
    req.organization = organization;
    // Compatibility with the existing UI and role checks.
    req.user.role = membership.role;
    req.memberships = memberships;

    if (membership.role === 'viewer' && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return res.status(403).json({ message: 'Viewer access is read-only for this organization workspace' });
    }

    return tenantStorage.run({ organizationId: String(organization._id) }, next);
  } catch (error) {
    console.error('Authentication failed:', error.message);
    return res.status(401).json({ message: 'Invalid or expired session' });
  }
}

export function requireRole(...roles) {
  const expanded = new Set(roles.flatMap(role => role === 'admin' ? ['owner', 'admin'] : [role]));
  return (req, res, next) => expanded.has(req.membership?.role)
    ? next()
    : res.status(403).json({ message: 'Insufficient permission for this organization workspace' });
}
