import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import PDFDocument from 'pdfkit';
import { parse } from 'csv-parse';
import { z } from 'zod';
import {
  Alert, AuditLog, BenchmarkRun, Detection, Incident, Integration, ModelVersion,
  Setting, TrafficEvent, User, Organization, Membership
} from '../models/index.js';
import { requireAuth, requireRole, migrateLegacyUser } from '../middleware/auth.js';
import { audit } from '../services/audit.js';
import {
  benchmarkInfo, benchmarkSample, bootstrapStatus, modelInfo, mlHealth,
  requestModelUpgrade, trainModel, predict
} from '../services/ml.js';
import { processTraffic } from '../services/detection.js';
import { asyncHandler, pageParams } from '../utils/http.js';
import { generateApiKey, hashApiKey } from '../utils/security.js';
import { tenantSettingKey, withTenant } from '../services/tenant-context.js';

const router = express.Router();
const upload = multer({
  dest: path.resolve('uploads/batch'),
  limits: { fileSize: Number(process.env.MAX_UPLOAD_MB || 500) * 1024 * 1024 }
});

const setupSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(10)
});

const publicUser = (user, membership) => ({
  id: user._id, name: user.name, email: user.email,
  role: membership?.role || 'viewer', platformRole: user.platformRole || 'user'
});
const signToken = user => jwt.sign(
  { sub: user._id.toString() },
  process.env.JWT_SECRET,
  { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
);
const slugify = value => String(value || 'organization').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'organization';
async function uniqueOrgSlug(name) {
  const base = slugify(name); let slug = base; let i = 2;
  while (await Organization.exists({ slug })) slug = `${base}-${i++}`;
  return slug;
}
async function sessionPayload(user, preferredOrganizationId) {
  const memberships = await Membership.find({ user: user._id, status: 'active' }).populate('organization').lean();
  const selected = memberships.find(m => String(m.organization?._id) === String(preferredOrganizationId || '')) || memberships[0];
  return {
    token: signToken(user),
    user: publicUser(user, selected),
    currentOrganization: selected?.organization || null,
    organizations: memberships.map(m => ({ ...m.organization, role: m.role, membershipId: m._id }))
  };
}

function scopeFilter(scope = 'operational') {
  if (scope === 'benchmark') return { environment: 'benchmark' };
  if (scope === 'test') return { environment: 'test' };
  if (scope === 'all') return {};
  return { environment: 'operational' };
}

async function syncModelVersion() {
  const m = await modelInfo();
  if (!m?.ready) return m;
  const exists = await ModelVersion.findOne({ version: m.version });
  if (!exists) {
    await ModelVersion.updateMany({}, { active: false });
    await ModelVersion.create({
      name: m.name || 'Mabeli Sentinel CICIDS2017',
      version: m.version,
      algorithm: m.algorithm,
      metrics: m.metrics,
      featureNames: m.feature_names || [],
      classes: m.classes || [],
      trainedAt: m.trained_at ? new Date(m.trained_at) : new Date(),
      dataset: m.dataset,
      trainingScope: m.training_scope,
      sourceName: m.source_name,
      sourceUrl: m.source_url,
      researchGrade: Boolean(m.research_grade),
      active: true,
      artifactHash: m.artifact_hash
    });
  } else if (!exists.active) {
    await ModelVersion.updateMany({}, { active: false });
    exists.active = true;
    await exists.save();
  }
  return m;
}

async function executeBenchmarkRun({ limit = 80, seed = 42, userId, io }) {
  const [model, sample] = await Promise.all([modelInfo(), benchmarkSample(limit, seed)]);
  if (!model?.ready) throw new Error('Production model is not ready');
  const run = await BenchmarkRun.create({
    sourceName: sample.info?.source_name || 'CICIDS2017 Benchmark',
    sourceUrl: sample.info?.source_url,
    datasetRecords: sample.info?.records,
    recordsRequested: sample.records.length,
    modelVersion: model.version,
    modelAlgorithm: model.algorithm,
    modelTrainingScope: model.training_scope,
    createdBy: userId
  });

  let processed = 0;
  let benignPredictions = 0;
  let maliciousPredictions = 0;
  let correctPredictions = 0;
  let binaryCorrectPredictions = 0;
  const attackDistribution = {};
  const groundTruthDistribution = {};

  try {
    for (const row of sample.records) {
      const result = await processTraffic({
        features: row.features,
        meta: {
          source: 'benchmark',
          environment: 'benchmark',
          sourceName: sample.info?.source_name || 'CICIDS2017 Benchmark',
          sourceIp: row.source_ip,
          destinationIp: row.destination_ip,
          rawLabel: row.ground_truth,
          benchmarkRunId: run._id.toString(),
          generateAlerts: false
        },
        io
      });
      const d = result.detection;
      processed += 1;
      if (d.prediction === 'benign') benignPredictions += 1;
      else maliciousPredictions += 1;
      if (d.isCorrect) correctPredictions += 1;
      const groundTruthBinary = String(row.ground_truth).toUpperCase() === 'BENIGN' ? 'benign' : 'malicious';
      if (d.prediction === groundTruthBinary) binaryCorrectPredictions += 1;
      attackDistribution[d.attackType] = (attackDistribution[d.attackType] || 0) + 1;
      groundTruthDistribution[row.ground_truth] = (groundTruthDistribution[row.ground_truth] || 0) + 1;
    }
    run.status = 'completed';
    run.recordsProcessed = processed;
    run.benignPredictions = benignPredictions;
    run.maliciousPredictions = maliciousPredictions;
    run.correctPredictions = correctPredictions;
    run.binaryCorrectPredictions = binaryCorrectPredictions;
    run.accuracy = processed ? correctPredictions / processed : 0;
    run.binaryAccuracy = processed ? binaryCorrectPredictions / processed : 0;
    run.attackDistribution = attackDistribution;
    run.groundTruthDistribution = groundTruthDistribution;
    run.completedAt = new Date();
    await run.save();
    return run.toObject();
  } catch (error) {
    run.status = 'failed';
    run.recordsProcessed = processed;
    run.error = error.message;
    run.completedAt = new Date();
    await run.save();
    throw error;
  }
}

const TEST_SCENARIOS = {
  benign: { label: 'BENIGN', title: 'Normal browsing flow', description: 'A genuine benign CICIDS2017-derived flow used to verify the non-malicious path.' },
  portscan: { label: 'PortScan', title: 'Port scan flow', description: 'A genuine PortScan-labelled CICIDS2017-derived flow used to exercise malicious detection.' },
  ddos: { label: 'DDoS', title: 'DDoS flow', description: 'A genuine DDoS-labelled CICIDS2017-derived flow used to exercise high-risk detection.' },
  dos_hulk: { label: 'DoS Hulk', title: 'DoS Hulk flow', description: 'A genuine DoS Hulk-labelled CICIDS2017-derived flow used to exercise denial-of-service detection.' },
  web_bruteforce: { label: 'Web Attack Brute Force', title: 'Web brute-force flow', description: 'A genuine web brute-force-labelled CICIDS2017-derived flow used to exercise web-attack classification.' }
};

async function getTestScenarioRecord(scenario, seed = 31415) {
  const spec = TEST_SCENARIOS[scenario];
  if (!spec) throw new Error('Unknown test scenario');
  const sample = await benchmarkSample(1000, seed);
  const record = sample.records.find(r => String(r.ground_truth).toLowerCase() === spec.label.toLowerCase());
  if (!record) throw new Error(`The current benchmark source does not contain ${spec.label}`);
  return { spec, record, info: sample.info };
}

async function createTestScenario({ scenario, userId, io }) {
  const { spec, record, info } = await getTestScenarioRecord(scenario, 31415 + Object.keys(TEST_SCENARIOS).indexOf(scenario));
  const result = await processTraffic({
    features: record.features,
    meta: {
      source: 'test',
      environment: 'test',
      sourceName: `Sentinel Test Kit · ${spec.title}`,
      sourceIp: record.source_ip,
      destinationIp: record.destination_ip,
      rawLabel: record.ground_truth,
      generateAlerts: true
    },
    io
  });
  return { scenario, spec, benchmark: info, groundTruth: record.ground_truth, ...result };
}

router.get('/setup/status', asyncHandler(async (_req, res) => {
  res.json({ needsSetup: false, mode: 'multi-organization' });
}));

router.post('/auth/register-organization', asyncHandler(async (req, res) => {
  const input = z.object({
    name: z.string().min(2), email: z.string().email(), password: z.string().min(10),
    organizationName: z.string().min(2), industry: z.string().max(120).optional(), size: z.string().max(80).optional(),
    country: z.string().max(120).optional(), website: z.string().max(240).optional()
  }).parse(req.body);
  if (await User.exists({ email: input.email.toLowerCase() })) return res.status(409).json({ message: 'An account with that email already exists. Sign in and create or join a workspace instead.' });
  const user = await User.create({ name: input.name, email: input.email, passwordHash: await bcrypt.hash(input.password, 12), role: 'admin' });
  const organization = await Organization.create({
    name: input.organizationName, slug: await uniqueOrgSlug(input.organizationName), industry: input.industry, size: input.size,
    country: input.country, website: input.website, createdBy: user._id
  });
  const membership = await Membership.create({ user: user._id, organization: organization._id, role: 'owner', status: 'active', invitedBy: user._id });
  await withTenant(organization._id, async () => {
    await Setting.create({ key: `organization:${organization._id}`, organizationName: organization.name });
    await AuditLog.create({ organization: organization._id, user: user._id, action: 'organization.create', entityType: 'Organization', entityId: organization._id.toString(), ip: req.ip });
  });
  await syncModelVersion().catch(() => {});
  res.status(201).json(await sessionPayload(user, organization._id));
}));

// Backward-compatible endpoint: it now creates an organization owner, never a platform-wide administrator.
router.post('/setup/admin', asyncHandler(async (req, res) => {
  const input = setupSchema.extend({ organizationName: z.string().min(2).default('My Organization') }).parse(req.body);
  req.body = { ...input, organizationName: input.organizationName };
  if (await User.exists({ email: input.email.toLowerCase() })) return res.status(409).json({ message: 'Account already exists' });
  const user = await User.create({ name: input.name, email: input.email, passwordHash: await bcrypt.hash(input.password, 12), role: 'admin' });
  const organization = await Organization.create({ name: input.organizationName, slug: await uniqueOrgSlug(input.organizationName), createdBy: user._id });
  await Membership.create({ user: user._id, organization: organization._id, role: 'owner', status: 'active', invitedBy: user._id });
  await withTenant(organization._id, async () => Setting.create({ key: `organization:${organization._id}`, organizationName: organization.name }));
  res.status(201).json(await sessionPayload(user, organization._id));
}));

router.post('/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = z.object({ email: z.string().email(), password: z.string().min(1) }).parse(req.body);
  const user = await User.findOne({ email: email.toLowerCase(), active: true });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ message: 'Invalid email or password' });
  user.lastLoginAt = new Date(); await user.save();
  await migrateLegacyUser(user);
  const membership = await Membership.findOne({ user: user._id, status: 'active' }).populate('organization');
  if (membership) await withTenant(membership.organization._id, async () => AuditLog.create({ organization: membership.organization._id, user: user._id, action: 'auth.login', entityType: 'User', entityId: user._id.toString(), ip: req.ip }));
  await syncModelVersion().catch(() => {});
  res.json(await sessionPayload(user));
}));

router.get('/auth/me', requireAuth, asyncHandler(async (req, res) => {
  const memberships = req.memberships || [];
  res.json({
    user: publicUser(req.user, req.membership), currentOrganization: req.organization,
    organizations: memberships.map(m => ({ ...m.organization, role: m.role, membershipId: m._id }))
  });
}));

router.get('/organizations', requireAuth, asyncHandler(async (req, res) => {
  res.json((req.memberships || []).map(m => ({ ...m.organization, role: m.role, membershipId: m._id })));
}));

router.post('/organizations', requireAuth, asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().min(2), industry: z.string().max(120).optional(), size: z.string().max(80).optional(), country: z.string().max(120).optional(), website: z.string().max(240).optional() }).parse(req.body);
  const organization = await Organization.create({ ...input, slug: await uniqueOrgSlug(input.name), createdBy: req.user._id });
  await Membership.create({ user: req.user._id, organization: organization._id, role: 'owner', status: 'active', invitedBy: req.user._id });
  await withTenant(organization._id, async () => Setting.create({ key: `organization:${organization._id}`, organizationName: organization.name }));
  res.status(201).json(organization);
}));

router.patch('/organizations/current', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().min(2).optional(), industry: z.string().max(120).optional(), size: z.string().max(80).optional(), country: z.string().max(120).optional(), website: z.string().max(240).optional(), onboardingCompleted: z.boolean().optional() }).parse(req.body);
  const update = { ...input };
  if ('onboardingCompleted' in update) { update.onboardingCompletedAt = update.onboardingCompleted ? new Date() : null; delete update.onboardingCompleted; }
  const org = await Organization.findByIdAndUpdate(req.organization._id, { $set: update }, { new: true });
  if (input.name) await Setting.findOneAndUpdate({ key: tenantSettingKey() }, { $set: { organizationName: input.name } }, { upsert: true });
  await audit(req, 'organization.update', 'Organization', org._id, update);
  res.json(org);
}));

router.get('/onboarding', requireAuth, asyncHandler(async (req, res) => {
  const [detections, integrations, members] = await Promise.all([
    Detection.countDocuments({}), Integration.countDocuments({ enabled: true }), Membership.countDocuments({ organization: req.organization._id, status: 'active' })
  ]);
  res.json({
    completed: Boolean(req.organization.onboardingCompletedAt),
    organization: req.organization,
    checklist: {
      organizationCreated: true,
      firstAnalysis: detections > 0,
      teamReady: members > 1,
      liveSourceConnected: integrations > 0
    }
  });
}));

router.get('/system/health', requireAuth, asyncHandler(async (_req, res) => {
  let ml = { ok: false };
  try { ml = await mlHealth(); } catch (e) { ml = { ok: false, error: e.message }; }
  res.json({ api: { ok: true }, database: { ok: true }, ml });
}));

router.get('/system/readiness', requireAuth, asyncHandler(async (_req, res) => {
  let ml = { ok: false };
  let model = { ready: false };
  let benchmark = { available: false };
  try {
    [ml, model, benchmark] = await Promise.all([mlHealth(), modelInfo(), benchmarkInfo()]);
  } catch (e) {
    ml = { ok: false, error: e.message };
  }
  const [operationalDetections, benchmarkDetections, testDetections, testAlerts, testIncidents, integrations, connectedIntegrations, lastRun] = await Promise.all([
    Detection.countDocuments({ environment: 'operational' }),
    Detection.countDocuments({ environment: 'benchmark' }),
    Detection.countDocuments({ environment: 'test' }),
    Alert.countDocuments({ environment: 'test' }),
    Incident.countDocuments({ environment: 'test' }),
    Integration.countDocuments({ enabled: true }),
    Integration.countDocuments({ enabled: true, lastSeenAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) } }),
    BenchmarkRun.findOne({ status: 'completed' }).sort({ completedAt: -1 }).lean()
  ]);
  res.json({
    ready: Boolean(ml.ok && model.ready && benchmark.available),
    services: { api: true, database: true, ml: Boolean(ml.ok) },
    model,
    ml,
    benchmark,
    traffic: { operational: operationalDetections, benchmark: benchmarkDetections, test: testDetections },
    test: { alerts: testAlerts, incidents: testIncidents },
    integrations: { configured: integrations, connected: connectedIntegrations },
    lastBenchmarkRun: lastRun
  });
}));

router.post('/system/validate', requireAuth, asyncHandler(async (req, res) => {
  const run = await executeBenchmarkRun({ limit: 12, seed: Date.now() % 100000, userId: req.user._id, io: req.app.get('io') });
  await audit(req, 'system.validate', 'BenchmarkRun', run._id, { records: run.recordsProcessed, binaryAccuracy: run.binaryAccuracy });
  res.status(201).json(run);
}));

router.get('/dashboard', requireAuth, asyncHandler(async (req, res) => {
  const scope = ['operational', 'benchmark', 'test', 'all'].includes(req.query.scope) ? req.query.scope : 'operational';
  const match = scopeFilter(scope);
  const since24 = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const recentMatch = { ...match };
  const timelineMatch = { ...match, createdAt: { $gte: since24 } };
  const alertEnv = scope === 'test' ? 'test' : 'operational';
  const alertScope = scope === 'all' ? { environment: { $in: ['operational', 'test'] } } : { environment: alertEnv };
  const incidentScope = scope === 'all' ? { environment: { $in: ['operational', 'test'] } } : { environment: alertEnv };
  const [total, benign, malicious, activeAlerts, criticalAlerts, openIncidents, recentDetections, attacks, timeline] = await Promise.all([
    Detection.countDocuments(match),
    Detection.countDocuments({ ...match, prediction: 'benign' }),
    Detection.countDocuments({ ...match, prediction: 'malicious' }),
    scope === 'benchmark' ? 0 : Alert.countDocuments({ ...alertScope, status: { $in: ['new', 'investigating'] } }),
    scope === 'benchmark' ? 0 : Alert.countDocuments({ ...alertScope, severity: 'critical', status: { $in: ['new', 'investigating'] } }),
    scope === 'benchmark' ? 0 : Incident.countDocuments({ ...incidentScope, status: { $ne: 'resolved' } }),
    Detection.find(recentMatch).sort({ createdAt: -1 }).limit(8).populate('trafficEvent').lean(),
    Detection.aggregate([
      { $match: { ...match, prediction: 'malicious' } },
      { $group: { _id: '$attackType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 8 }
    ]),
    Detection.aggregate([
      { $match: timelineMatch },
      { $group: { _id: { h: { $hour: '$createdAt' }, prediction: '$prediction' }, count: { $sum: 1 } } },
      { $sort: { '_id.h': 1 } }
    ])
  ]);
  res.json({ scope, total, benign, malicious, activeAlerts, criticalAlerts, openIncidents, recentDetections, attacks, timeline });
}));

router.post('/benchmark/ensure', requireAuth, asyncHandler(async (req, res) => {
  const existing = await Detection.countDocuments({ environment: 'benchmark' });
  if (existing) {
    const lastRun = await BenchmarkRun.findOne({ status: 'completed' }).sort({ completedAt: -1 }).lean();
    return res.json({ created: false, existing, run: lastRun });
  }
  const run = await executeBenchmarkRun({ limit: 60, seed: 42, userId: req.user._id, io: req.app.get('io') });
  await audit(req, 'benchmark.bootstrap', 'BenchmarkRun', run._id, { records: run.recordsProcessed });
  res.status(201).json({ created: true, run });
}));

router.get('/benchmark', requireAuth, asyncHandler(async (_req, res) => {
  const [info, model, lastRuns, total, malicious, correct, binaryCorrect, attacks] = await Promise.all([
    benchmarkInfo(), modelInfo(), BenchmarkRun.find().sort({ createdAt: -1 }).limit(8).lean(),
    Detection.countDocuments({ environment: 'benchmark' }),
    Detection.countDocuments({ environment: 'benchmark', prediction: 'malicious' }),
    Detection.countDocuments({ environment: 'benchmark', isCorrect: true }),
    Detection.countDocuments({ environment: 'benchmark', $expr: {
      $eq: [
        '$prediction',
        { $cond: [{ $eq: [{ $toUpper: '$groundTruth' }, 'BENIGN'] }, 'benign', 'malicious'] }
      ]
    } }),
    Detection.aggregate([
      { $match: { environment: 'benchmark', prediction: 'malicious' } },
      { $group: { _id: '$attackType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ])
  ]);
  res.json({ info, model, lastRuns, total, malicious, correct, binaryCorrect, attacks });
}));

router.post('/benchmark/run', requireAuth, asyncHandler(async (req, res) => {
  const input = z.object({ limit: z.number().int().min(10).max(1000).default(100), seed: z.number().int().optional() }).parse(req.body || {});
  const run = await executeBenchmarkRun({ limit: input.limit, seed: input.seed ?? (Date.now() % 100000), userId: req.user._id, io: req.app.get('io') });
  await audit(req, 'benchmark.run', 'BenchmarkRun', run._id, { records: run.recordsProcessed, binaryAccuracy: run.binaryAccuracy, accuracy: run.accuracy });
  res.status(201).json(run);
}));

router.delete('/benchmark/data', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const events = await TrafficEvent.find({ environment: 'benchmark' }).select('_id').lean();
  const ids = events.map(x => x._id);
  await Promise.all([
    Detection.deleteMany({ environment: 'benchmark' }),
    TrafficEvent.deleteMany({ environment: 'benchmark' }),
    BenchmarkRun.deleteMany({})
  ]);
  await audit(req, 'benchmark.clear', 'TrafficEvent', null, { events: ids.length });
  res.json({ cleared: ids.length });
}));

router.post('/analysis/single', requireAuth, asyncHandler(async (req, res) => {
  const input = z.object({ features: z.record(z.any()), meta: z.record(z.any()).optional() }).parse(req.body);
  const requestedEnvironment = input.meta?.environment === 'test' ? 'test' : 'operational';
  const result = await processTraffic({
    features: input.features,
    meta: { ...(input.meta || {}), source: requestedEnvironment === 'test' ? 'test' : 'manual', environment: requestedEnvironment },
    io: req.app.get('io')
  });
  await audit(req, 'analysis.single', 'Detection', result.detection._id, { attackType: result.detection.attackType });
  res.status(201).json(result);
}));

router.post('/analysis/batch', requireAuth, upload.single('file'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'CSV file is required' });
  const maxRows = Math.min(50000, Math.max(1, Number(req.body.maxRows || 5000)));
  const records = [];
  await new Promise((resolve, reject) => {
    fs.createReadStream(req.file.path)
      .pipe(parse({ columns: true, skip_empty_lines: true, trim: true }))
      .on('data', row => { if (records.length < maxRows) records.push(row); })
      .on('end', resolve).on('error', reject);
  });
  fs.unlink(req.file.path, () => {});
  if (!records.length) return res.status(400).json({ message: 'No CSV records were found' });
  const labelled = records.some(row => row.Label || row.label);
  const requestedEnvironment = ['operational', 'benchmark', 'test'].includes(req.body.environment) ? req.body.environment : '';
  const environment = requestedEnvironment || (labelled ? 'benchmark' : 'operational');
  const results = [];
  for (const row of records) {
    const rawLabel = row.Label || row.label;
    const features = {};
    for (const [k, v] of Object.entries(row)) {
      if (['Label', 'label', 'Label_Binary', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'].includes(k)) continue;
      const n = Number(v);
      if (Number.isFinite(n)) features[k.trim()] = n;
    }
    try {
      const r = await processTraffic({
        features,
        meta: {
          source: 'batch', environment, sourceName: req.file.originalname, rawLabel,
          sourceIp: row['Source IP'], destinationIp: row['Destination IP'],
          generateAlerts: environment !== 'benchmark'
        },
        io: req.app.get('io')
      });
      results.push({ id: r.detection._id, prediction: r.detection.prediction, attackType: r.detection.attackType, confidence: r.detection.confidence, severity: r.detection.severity, isCorrect: r.detection.isCorrect });
    } catch (e) {
      results.push({ error: e.response?.data?.detail || e.message });
    }
  }
  await audit(req, 'analysis.batch', 'TrafficEvent', null, { file: req.file.originalname, rows: records.length, environment });
  res.status(201).json({ processed: records.length, environment, results });
}));

router.get('/detections', requireAuth, asyncHandler(async (req, res) => {
  const { page, limit, skip } = pageParams(req);
  const query = {};
  if (req.query.environment && ['operational', 'benchmark', 'test'].includes(req.query.environment)) query.environment = req.query.environment;
  if (req.query.prediction) query.prediction = req.query.prediction;
  if (req.query.attackType) query.attackType = req.query.attackType;
  if (req.query.severity) query.severity = req.query.severity;
  if (req.query.from || req.query.to) query.createdAt = {};
  if (req.query.from) query.createdAt.$gte = new Date(req.query.from);
  if (req.query.to) query.createdAt.$lte = new Date(req.query.to);
  const [items, total] = await Promise.all([
    Detection.find(query).populate('trafficEvent').sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Detection.countDocuments(query)
  ]);
  res.json({ items, total, page, pages: Math.ceil(total / limit) || 1 });
}));

router.get('/detections/:id', requireAuth, asyncHandler(async (req, res) => {
  const item = await Detection.findById(req.params.id).populate('trafficEvent').lean();
  if (!item) return res.status(404).json({ message: 'Detection not found' });
  res.json(item);
}));

router.delete('/detections/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const detection = await Detection.findById(req.params.id);
  if (!detection) return res.status(404).json({ message: 'Detection not found' });
  const linkedAlerts = await Alert.find({ detection: detection._id }).select('_id').lean();
  const alertIds = linkedAlerts.map(x => x._id);
  if (alertIds.length) {
    await Incident.updateMany({ alerts: { $in: alertIds } }, { $pull: { alerts: { $in: alertIds } } });
    await Alert.deleteMany({ _id: { $in: alertIds } });
  }
  await Detection.deleteOne({ _id: detection._id });
  await TrafficEvent.deleteOne({ _id: detection.trafficEvent });
  await audit(req, 'detection.delete', 'Detection', detection._id, { environment: detection.environment, linkedAlertsDeleted: alertIds.length });
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('detection:delete', { id: detection._id.toString() });
  res.json({ deleted: true, linkedAlertsDeleted: alertIds.length });
}));

router.get('/alerts', requireAuth, asyncHandler(async (req, res) => {
  const { page, limit, skip } = pageParams(req);
  const environment = req.query.environment === 'test' ? 'test' : 'operational';
  const query = { environment };
  if (req.query.status) query.status = req.query.status;
  if (req.query.severity) query.severity = req.query.severity;
  const [items, total] = await Promise.all([
    Alert.find(query).populate({ path: 'detection', populate: { path: 'trafficEvent' } }).populate('assignee', 'name email').sort({ updatedAt: -1 }).skip(skip).limit(limit).lean(),
    Alert.countDocuments(query)
  ]);
  res.json({ items, total, page, pages: Math.ceil(total / limit) || 1 });
}));

router.patch('/alerts/:id', requireAuth, asyncHandler(async (req, res) => {
  const allowed = z.object({
    status: z.enum(['new', 'investigating', 'resolved', 'false_positive']).optional(),
    assignee: z.string().nullable().optional(),
    note: z.string().max(4000).optional()
  }).parse(req.body);
  const alert = await Alert.findById(req.params.id);
  if (!alert) return res.status(404).json({ message: 'Alert not found' });
  if (allowed.status) alert.status = allowed.status;
  if ('assignee' in allowed) alert.assignee = allowed.assignee || undefined;
  if (allowed.note) alert.notes.push({ body: allowed.note, author: req.user._id });
  await alert.save();
  await audit(req, 'alert.update', 'Alert', alert._id, allowed);
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('alert:update', alert);
  res.json(alert);
}));


router.delete('/alerts/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const alert = await Alert.findById(req.params.id);
  if (!alert) return res.status(404).json({ message: 'Alert not found' });
  await Incident.updateMany({ alerts: alert._id }, { $pull: { alerts: alert._id } });
  await Alert.deleteOne({ _id: alert._id });
  await audit(req, 'alert.delete', 'Alert', alert._id, { environment: alert.environment, title: alert.title });
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('alert:update', { deleted: true, id: alert._id.toString() });
  res.json({ deleted: true });
}));


router.post('/incidents', requireAuth, asyncHandler(async (req, res) => {
  const input = z.object({
    title: z.string().min(3), summary: z.string().optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    environment: z.enum(['operational', 'test']).default('operational'),
    alerts: z.array(z.string()).default([]), assignee: z.string().optional()
  }).parse(req.body);
  const incident = await Incident.create({ ...input, timeline: [{ action: 'created', note: input.summary || 'Incident opened', user: req.user._id }] });
  await audit(req, 'incident.create', 'Incident', incident._id, input);
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('incident:new', incident);
  res.status(201).json(incident);
}));

router.get('/incidents', requireAuth, asyncHandler(async (req, res) => {
  const query = {};
  if (req.query.environment && ['operational', 'test'].includes(req.query.environment)) query.environment = req.query.environment;
  if (req.query.status && ['open', 'investigating', 'contained', 'resolved'].includes(req.query.status)) query.status = req.query.status;
  if (req.query.severity && ['low', 'medium', 'high', 'critical'].includes(req.query.severity)) query.severity = req.query.severity;
  res.json(await Incident.find(query).populate('alerts').populate('assignee', 'name email').sort({ updatedAt: -1 }).lean());
}));

router.get('/incidents/:id', requireAuth, asyncHandler(async (req, res) => {
  const item = await Incident.findById(req.params.id)
    .populate({ path: 'alerts', populate: { path: 'detection', populate: { path: 'trafficEvent' } } })
    .populate('assignee', 'name email')
    .populate('timeline.user', 'name email')
    .lean();
  if (!item) return res.status(404).json({ message: 'Incident not found' });
  res.json(item);
}));

router.patch('/incidents/:id', requireAuth, asyncHandler(async (req, res) => {
  const incident = await Incident.findById(req.params.id);
  if (!incident) return res.status(404).json({ message: 'Incident not found' });
  const input = z.object({
    status: z.enum(['open', 'investigating', 'contained', 'resolved']).optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    assignee: z.string().nullable().optional(), note: z.string().max(4000).optional(),
    addAlerts: z.array(z.string()).optional()
  }).parse(req.body);
  if (input.status) incident.status = input.status;
  if (input.severity) incident.severity = input.severity;
  if ('assignee' in input) incident.assignee = input.assignee || undefined;
  if (input.addAlerts) for (const id of input.addAlerts) if (!incident.alerts.some(a => String(a) === id)) incident.alerts.push(id);
  if (input.note) incident.timeline.push({ action: input.status ? `status:${input.status}` : 'note', note: input.note, user: req.user._id });
  await incident.save();
  await audit(req, 'incident.update', 'Incident', incident._id, input);
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('incident:update', incident);
  res.json(incident);
}));


router.delete('/incidents/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const incident = await Incident.findByIdAndDelete(req.params.id);
  if (!incident) return res.status(404).json({ message: 'Incident not found' });
  await audit(req, 'incident.delete', 'Incident', incident._id, { environment: incident.environment, title: incident.title });
  req.app.get('io')?.to(`org:${req.organization._id}`).emit('incident:update', { deleted: true, id: incident._id.toString() });
  res.json({ deleted: true });
}));


router.get('/analytics', requireAuth, asyncHandler(async (req, res) => {
  const days = Math.min(365, Math.max(1, Number(req.query.days || 30)));
  const since = new Date(Date.now() - days * 86400000);
  const scope = ['operational', 'benchmark', 'test', 'all'].includes(req.query.scope) ? req.query.scope : 'operational';
  const match = { ...scopeFilter(scope), createdAt: { $gte: since } };
  const [daily, attacks, severity, confidence, falsePositives] = await Promise.all([
    Detection.aggregate([{ $match: match }, { $group: { _id: { d: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, p: '$prediction' }, count: { $sum: 1 } } }, { $sort: { '_id.d': 1 } }]),
    Detection.aggregate([{ $match: { ...match, prediction: 'malicious' } }, { $group: { _id: '$attackType', count: { $sum: 1 }, avgConfidence: { $avg: '$confidence' } } }, { $sort: { count: -1 } }]),
    Detection.aggregate([{ $match: match }, { $group: { _id: '$severity', count: { $sum: 1 } } }]),
    Detection.aggregate([{ $match: match }, { $group: { _id: null, avg: { $avg: '$confidence' }, min: { $min: '$confidence' }, max: { $max: '$confidence' } } }]),
    scope === 'benchmark' ? 0 : Alert.countDocuments({ ...(scope === 'all' ? { environment: { $in: ['operational', 'test'] } } : { environment: scope === 'test' ? 'test' : 'operational' }), status: 'false_positive', updatedAt: { $gte: since } })
  ]);
  res.json({ scope, days, daily, attacks, severity, confidence: confidence[0] || { avg: 0, min: 0, max: 0 }, falsePositives });
}));

router.get('/reports/security.csv', requireAuth, asyncHandler(async (req, res) => {
  const days = Math.min(365, Math.max(1, Number(req.query.days || 30)));
  const since = new Date(Date.now() - days * 86400000);
  const scope = ['operational', 'benchmark', 'test', 'all'].includes(req.query.scope) ? req.query.scope : 'operational';
  const rows = await Detection.find({ ...scopeFilter(scope), createdAt: { $gte: since } }).populate('trafficEvent').sort({ createdAt: -1 }).lean();
  const csvEsc = v => `"${String(v ?? '').replaceAll('"', '""')}"`;
  const head = ['Time', 'Environment', 'Prediction', 'Attack Type', 'Ground Truth', 'Confidence', 'Risk Score', 'Severity', 'Source', 'Source IP', 'Destination IP'];
  const body = rows.map(r => [r.createdAt, r.environment, r.prediction, r.attackType, r.groundTruth, r.confidence, r.riskScore, r.severity, r.trafficEvent?.sourceName, r.trafficEvent?.sourceIp, r.trafficEvent?.destinationIp].map(csvEsc).join(','));
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="mabeli-security-report-${Date.now()}.csv"`);
  res.send([head.join(','), ...body].join('\n'));
}));

router.get('/reports/security.pdf', requireAuth, asyncHandler(async (req, res) => {
  const days = Math.min(365, Math.max(1, Number(req.query.days || 30)));
  const since = new Date(Date.now() - days * 86400000);
  const scope = ['operational', 'benchmark', 'test', 'all'].includes(req.query.scope) ? req.query.scope : 'operational';
  const match = { ...scopeFilter(scope), createdAt: { $gte: since } };
  const [total, malicious, alerts, incidents, attacks] = await Promise.all([
    Detection.countDocuments(match),
    Detection.countDocuments({ ...match, prediction: 'malicious' }),
    scope === 'benchmark' ? 0 : Alert.countDocuments({ ...(scope === 'all' ? { environment: { $in: ['operational', 'test'] } } : { environment: scope === 'test' ? 'test' : 'operational' }), createdAt: { $gte: since } }),
    scope === 'benchmark' ? 0 : Incident.countDocuments({ ...(scope === 'all' ? { environment: { $in: ['operational', 'test'] } } : { environment: scope === 'test' ? 'test' : 'operational' }), createdAt: { $gte: since } }),
    Detection.aggregate([{ $match: { ...match, prediction: 'malicious' } }, { $group: { _id: '$attackType', count: { $sum: 1 } } }, { $sort: { count: -1 } }])
  ]);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="mabeli-security-report-${Date.now()}.pdf"`);
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);
  doc.fontSize(22).text('Mabeli Sentinel Security Report');
  doc.moveDown().fontSize(10).text(`${req.organization.name} • Mabeli Sentinel by Mabeli Technology • ${scope} scope • Last ${days} days • Generated ${new Date().toISOString()}`);
  doc.moveDown().fontSize(14).text('Executive summary');
  doc.fontSize(11).text(`Traffic detections: ${total}\nMalicious detections: ${malicious}\nAlerts created: ${alerts}\nIncidents opened: ${incidents}`);
  doc.moveDown().fontSize(14).text('Attack distribution');
  doc.fontSize(11);
  if (!attacks.length) doc.text('No malicious detections in this period.');
  else attacks.forEach(a => doc.text(`${a._id}: ${a.count}`));
  doc.end();
}));


router.get('/test-kit', requireAuth, asyncHandler(async (_req, res) => {
  const [benchmark, detections, alerts, incidents] = await Promise.all([
    benchmarkInfo(),
    Detection.countDocuments({ environment: 'test' }),
    Alert.countDocuments({ environment: 'test' }),
    Incident.countDocuments({ environment: 'test' })
  ]);
  const availableLabels = new Set((benchmark.classes || []).map(x => String(x).toLowerCase()));
  res.json({
    benchmark,
    counts: { detections, alerts, incidents },
    scenarios: Object.entries(TEST_SCENARIOS).map(([id, spec]) => ({ id, ...spec, available: availableLabels.has(spec.label.toLowerCase()) }))
  });
}));

router.post('/test-kit/scenario', requireAuth, asyncHandler(async (req, res) => {
  const input = z.object({ scenario: z.enum(['benign', 'portscan', 'ddos', 'dos_hulk', 'web_bruteforce']) }).parse(req.body);
  const result = await createTestScenario({ scenario: input.scenario, userId: req.user._id, io: req.app.get('io') });
  await audit(req, 'test.scenario', 'Detection', result.detection._id, { scenario: input.scenario, groundTruth: result.groundTruth, prediction: result.detection.prediction });
  res.status(201).json({
    scenario: input.scenario,
    detection: result.detection,
    traffic: result.traffic,
    alert: result.alert,
    source: result.benchmark?.source_name,
    groundTruth: result.groundTruth || result.detection.groundTruth
  });
}));

router.post('/test-kit/full', requireAuth, asyncHandler(async (req, res) => {
  const requested = ['benign', 'portscan', 'ddos', 'dos_hulk', 'web_bruteforce'];
  const results = [];
  for (const scenario of requested) {
    try {
      const item = await createTestScenario({ scenario, userId: req.user._id, io: req.app.get('io') });
      results.push({ scenario, detection: item.detection, traffic: item.traffic, alert: item.alert });
    } catch (e) {
      results.push({ scenario, error: e.message });
    }
  }

  let alert = results.find(x => x.alert)?.alert || null;
  if (!alert) {
    const sample = await benchmarkSample(1000, 27182);
    for (const record of sample.records.slice(0, 80)) {
      if (String(record.ground_truth).toUpperCase() === 'BENIGN') continue;
      const prediction = await predict(record.features);
      if (prediction.prediction === 'malicious') {
        const extra = await processTraffic({
          features: record.features,
          meta: {
            source: 'test', environment: 'test', sourceName: 'Sentinel Test Kit · Alert exercise',
            sourceIp: record.source_ip, destinationIp: record.destination_ip,
            rawLabel: record.ground_truth, generateAlerts: true
          },
          io: req.app.get('io')
        });
        alert = extra.alert;
        results.push({ scenario: 'alert_exercise', detection: extra.detection, traffic: extra.traffic, alert: extra.alert });
        if (alert) break;
      }
    }
  }

  let incident = null;
  if (alert) {
    incident = await Incident.create({
      title: `[TEST] ${alert.title}`,
      summary: 'Created by the Mabeli Sentinel Test Centre from genuine CICIDS2017-derived traffic. This is isolated test evidence, not a real Mabeli Technology incident.',
      environment: 'test',
      severity: alert.severity,
      alerts: [alert._id],
      timeline: [{ action: 'created', note: 'Automated setup-verification incident created from a test alert.', user: req.user._id }]
    });
    alert.status = 'investigating';
    alert.notes.push({ body: 'Linked to an isolated Test Centre incident.', author: req.user._id });
    await alert.save();
  }

  await audit(req, 'test.full', 'Incident', incident?._id, { detections: results.filter(x => x.detection).length, alertCreated: Boolean(alert), incidentCreated: Boolean(incident) });
  res.status(201).json({ results, alert, incident });
}));

router.delete('/test-kit/data', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const events = await TrafficEvent.find({ environment: 'test' }).select('_id').lean();
  const [detections, alerts, incidents] = await Promise.all([
    Detection.countDocuments({ environment: 'test' }),
    Alert.countDocuments({ environment: 'test' }),
    Incident.countDocuments({ environment: 'test' })
  ]);
  await Promise.all([
    Detection.deleteMany({ environment: 'test' }),
    Alert.deleteMany({ environment: 'test' }),
    Incident.deleteMany({ environment: 'test' }),
    TrafficEvent.deleteMany({ environment: 'test' })
  ]);
  await audit(req, 'test.clear', 'TrafficEvent', null, { events: events.length, detections, alerts, incidents });
  res.json({ cleared: { events: events.length, detections, alerts, incidents } });
}));


router.get('/model', requireAuth, asyncHandler(async (_req, res) => {
  try {
    const result = await syncModelVersion();
    res.json(result);
  } catch (e) {
    res.status(503).json({ ready: false, message: e.response?.data?.detail || e.message });
  }
}));

router.post('/model/upgrade', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const result = await requestModelUpgrade();
  await audit(req, 'model.upgrade.request', 'ModelVersion', null, result);
  res.status(202).json(result);
}));

router.get('/model/bootstrap', requireAuth, asyncHandler(async (_req, res) => res.json(await bootstrapStatus())));

router.post('/model/train', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const payload = z.object({ dataset_path: z.string().min(1), sample_limit: z.number().int().positive().optional(), random_state: z.number().int().optional() }).parse(req.body);
  const result = await trainModel(payload);
  await ModelVersion.updateMany({}, { active: false });
  await ModelVersion.create({
    name: 'Mabeli Sentinel CICIDS2017', version: result.version, algorithm: result.algorithm,
    metrics: result.metrics, featureNames: result.feature_names, classes: result.classes,
    trainedAt: new Date(result.trained_at), dataset: payload.dataset_path,
    trainingScope: result.training_scope, sourceName: result.source_name, sourceUrl: result.source_url,
    researchGrade: Boolean(result.research_grade), active: true, artifactHash: result.artifact_hash
  });
  await audit(req, 'model.train', 'ModelVersion', result.version, { dataset: payload.dataset_path, algorithm: result.algorithm });
  res.json(result);
}));

router.get('/settings', requireAuth, asyncHandler(async (_req, res) => {
  res.json(await Setting.findOneAndUpdate({ key: tenantSettingKey() }, { $setOnInsert: { key: tenantSettingKey(), organizationName: _req.organization?.name } }, { upsert: true, new: true }).lean());
}));

router.patch('/settings', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({
    organizationName: z.string().min(2).optional(), maliciousThreshold: z.number().min(0).max(1).optional(),
    alertGroupingMinutes: z.number().int().min(1).max(1440).optional(),
    severityThresholds: z.object({ medium: z.number().min(0).max(100), high: z.number().min(0).max(100), critical: z.number().min(0).max(100) }).optional()
  }).parse(req.body);
  const settings = await Setting.findOneAndUpdate({ key: tenantSettingKey() }, { $set: input }, { upsert: true, new: true });
  if (input.organizationName) await Organization.findByIdAndUpdate(req.organization._id, { $set: { name: input.organizationName } });
  await audit(req, 'settings.update', 'Setting', settings._id, input);
  res.json(settings);
}));

router.get('/users', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const memberships = await Membership.find({ organization: req.organization._id }).populate('user', 'name email active lastLoginAt').sort({ createdAt: -1 }).lean();
  res.json(memberships.map(m => ({
    _id: m.user?._id, membershipId: m._id, name: m.user?.name, email: m.user?.email, role: m.role,
    active: m.status === 'active' && Boolean(m.user?.active), membershipStatus: m.status, lastLoginAt: m.user?.lastLoginAt, createdAt: m.createdAt
  })));
}));

router.post('/users', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().min(2), email: z.string().email(), password: z.string().min(10).optional(), role: z.enum(['owner','admin','analyst','viewer']).default('analyst') }).parse(req.body);
  let user = await User.findOne({ email: input.email.toLowerCase() });
  if (!user) {
    if (!input.password) return res.status(400).json({ message: 'A temporary password of at least 10 characters is required for a new account' });
    user = await User.create({ name: input.name, email: input.email, passwordHash: await bcrypt.hash(input.password, 12), role: input.role === 'admin' || input.role === 'owner' ? 'admin' : 'analyst' });
  } else if (input.name && user.name !== input.name) { user.name = input.name; await user.save(); }
  const existing = await Membership.findOne({ user: user._id, organization: req.organization._id });
  if (existing?.status === 'active') return res.status(409).json({ message: 'That user already belongs to this organization' });
  const membership = existing || new Membership({ user: user._id, organization: req.organization._id });
  membership.role = input.role; membership.status = 'active'; membership.revokedAt = undefined; membership.invitedBy = req.user._id; await membership.save();
  await audit(req, 'member.add', 'Membership', membership._id, { email: user.email, role: membership.role });
  res.status(201).json({ id: user._id, membershipId: membership._id, name: user.name, email: user.email, role: membership.role, active: true });
}));

router.patch('/users/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({ role: z.enum(['owner','admin','analyst','viewer']).optional(), active: z.boolean().optional(), name: z.string().min(2).optional() }).parse(req.body);
  const user = await User.findById(req.params.id);
  const membership = await Membership.findOne({ user: req.params.id, organization: req.organization._id });
  if (!user || !membership) return res.status(404).json({ message: 'Organization member not found' });
  if (String(req.user._id) === req.params.id && input.active === false) return res.status(400).json({ message: 'You cannot revoke your own workspace access' });
  const removingOwner = membership.role === 'owner' && membership.status === 'active' && ((input.role && input.role !== 'owner') || input.active === false);
  if (removingOwner) {
    const owners = await Membership.countDocuments({ organization: req.organization._id, role: 'owner', status: 'active' });
    if (owners <= 1) return res.status(400).json({ message: 'The organization must keep at least one active owner' });
  }
  if (input.name) user.name = input.name;
  if (input.role) membership.role = input.role;
  if (typeof input.active === 'boolean') { membership.status = input.active ? 'active' : 'revoked'; membership.revokedAt = input.active ? undefined : new Date(); }
  await Promise.all([user.save(), membership.save()]);
  await audit(req, 'member.update', 'Membership', membership._id, input);
  res.json({ _id: user._id, membershipId: membership._id, name: user.name, email: user.email, role: membership.role, active: membership.status === 'active', membershipStatus: membership.status });
}));

router.post('/users/:id/revoke', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  if (String(req.user._id) === req.params.id) return res.status(400).json({ message: 'You cannot revoke your own workspace access' });
  const membership = await Membership.findOne({ user: req.params.id, organization: req.organization._id });
  if (!membership) return res.status(404).json({ message: 'Organization member not found' });
  if (membership.role === 'owner') {
    const owners = await Membership.countDocuments({ organization: req.organization._id, role: 'owner', status: 'active' });
    if (owners <= 1) return res.status(400).json({ message: 'The organization must keep at least one active owner' });
  }
  membership.status = 'revoked'; membership.revokedAt = new Date(); await membership.save();
  await audit(req, 'member.revoke', 'Membership', membership._id, { user: req.params.id });
  res.json({ revoked: true });
}));

router.delete('/users/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  if (String(req.user._id) === req.params.id) return res.status(400).json({ message: 'You cannot remove yourself from the current workspace' });
  const membership = await Membership.findOne({ user: req.params.id, organization: req.organization._id });
  if (!membership) return res.status(404).json({ message: 'Organization member not found' });
  if (membership.role === 'owner' && membership.status === 'active') {
    const owners = await Membership.countDocuments({ organization: req.organization._id, role: 'owner', status: 'active' });
    if (owners <= 1) return res.status(400).json({ message: 'The organization must keep at least one active owner' });
  }
  await Membership.deleteOne({ _id: membership._id });
  await audit(req, 'member.remove', 'Membership', membership._id, { user: req.params.id });
  res.json({ deleted: true, accountPreserved: true });
}));

router.get('/audit', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const { page, limit, skip } = pageParams(req);
  const [items, total] = await Promise.all([
    AuditLog.find().populate('user', 'name email').sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    AuditLog.countDocuments()
  ]);
  res.json({ items, total, page, pages: Math.ceil(total / limit) || 1 });
}));

router.get('/integrations', requireAuth, requireRole('admin'), asyncHandler(async (_req, res) => {
  res.json(await Integration.find().select('-apiKeyHash').sort({ createdAt: -1 }).lean());
}));

router.post('/integrations', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().min(2), type: z.enum(['flow_forwarder', 'cicflowmeter', 'custom']) }).parse(req.body);
  const apiKey = generateApiKey();
  const integration = await Integration.create({ ...input, apiKeyHash: hashApiKey(apiKey), keyPrefix: apiKey.slice(0, 10), createdBy: req.user._id });
  await audit(req, 'integration.create', 'Integration', integration._id, { name: integration.name, type: integration.type });
  res.status(201).json({ integration: { id: integration._id, name: integration.name, type: integration.type, keyPrefix: integration.keyPrefix, enabled: integration.enabled }, apiKey });
}));

router.patch('/integrations/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const input = z.object({ enabled: z.boolean().optional(), name: z.string().min(2).optional() }).parse(req.body);
  const integration = await Integration.findByIdAndUpdate(req.params.id, { $set: input }, { new: true }).select('-apiKeyHash');
  if (!integration) return res.status(404).json({ message: 'Integration not found' });
  await audit(req, 'integration.update', 'Integration', integration._id, input);
  res.json(integration);
}));


router.delete('/integrations/:id', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const integration = await Integration.findByIdAndDelete(req.params.id);
  if (!integration) return res.status(404).json({ message: 'Integration not found' });
  await audit(req, 'integration.delete', 'Integration', integration._id, { name: integration.name, type: integration.type });
  res.json({ deleted: true });
}));



router.post('/ingest/ping', asyncHandler(async (req, res) => {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ message: 'x-api-key is required' });
  const integration = await Integration.findOne({ apiKeyHash: hashApiKey(String(key)), enabled: true }).setOptions({ bypassTenant: true });
  if (!integration) return res.status(401).json({ message: 'Invalid integration key' });
  integration.lastSeenAt = new Date();
  await integration.save();
  res.json({ ok: true, integration: integration.name, receivedAt: integration.lastSeenAt });
}));


router.post('/ingest', asyncHandler(async (req, res) => {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ message: 'x-api-key is required' });
  const integration = await Integration.findOne({ apiKeyHash: hashApiKey(String(key)), enabled: true }).setOptions({ bypassTenant: true });
  if (!integration) return res.status(401).json({ message: 'Invalid integration key' });
  const input = z.object({ features: z.record(z.any()), meta: z.record(z.any()).optional() }).parse(req.body);
  integration.lastSeenAt = new Date();
  await integration.save();
  const result = await withTenant(integration.organization, () => processTraffic({
    features: input.features,
    meta: { ...(input.meta || {}), source: 'live', environment: 'operational', sourceName: integration.name },
    io: req.app.get('io')
  }));
  res.status(201).json({ detection: result.detection, alert: result.alert });
}));

router.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof z.ZodError) return res.status(400).json({ message: 'Validation failed', issues: err.issues });
  if (err.code === 11000) return res.status(409).json({ message: 'A record with that value already exists' });
  res.status(err.response?.status || 500).json({ message: err.response?.data?.detail || err.message || 'Unexpected server error' });
});

export default router;
