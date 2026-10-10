import mongoose from 'mongoose';
import { tenantPlugin } from '../services/tenant-context.js';

const { Schema, model } = mongoose;

const organizationSchema = new Schema({
  name: { type: String, required: true, trim: true },
  slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
  industry: { type: String, trim: true },
  size: { type: String, trim: true },
  country: { type: String, trim: true },
  website: { type: String, trim: true },
  onboardingCompletedAt: Date,
  active: { type: Boolean, default: true },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const userSchema = new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  active: { type: Boolean, default: true },
  platformRole: { type: String, enum: ['user', 'platform_admin'], default: 'user' },
  // Kept for backward compatibility. Organization permissions live on Membership.
  role: { type: String, enum: ['admin', 'analyst'], default: 'analyst' },
  lastLoginAt: Date
}, { timestamps: true });

const membershipSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  organization: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  role: { type: String, enum: ['owner', 'admin', 'analyst', 'viewer'], default: 'analyst' },
  status: { type: String, enum: ['active', 'revoked'], default: 'active', index: true },
  invitedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  revokedAt: Date
}, { timestamps: true });
membershipSchema.index({ user: 1, organization: 1 }, { unique: true });

const trafficEventSchema = new Schema({
  source: { type: String, enum: ['manual', 'batch', 'live', 'replay', 'benchmark', 'test'], default: 'manual' },
  environment: { type: String, enum: ['operational', 'benchmark', 'test'], default: 'operational', index: true },
  sourceName: { type: String, default: 'Analyst input' },
  sourceIp: String, destinationIp: String, sourcePort: Number, destinationPort: Number, protocol: String,
  features: { type: Schema.Types.Mixed, required: true }, rawLabel: String, benchmarkRunId: String,
  receivedAt: { type: Date, default: Date.now }, processingMs: Number,
  status: { type: String, enum: ['processed', 'failed'], default: 'processed' }, error: String
}, { timestamps: true });
trafficEventSchema.plugin(tenantPlugin);

const detectionSchema = new Schema({
  trafficEvent: { type: Schema.Types.ObjectId, ref: 'TrafficEvent', required: true, index: true },
  environment: { type: String, enum: ['operational', 'benchmark', 'test'], default: 'operational', index: true },
  prediction: { type: String, enum: ['benign', 'malicious'], required: true, index: true }, attackType: { type: String, default: 'BENIGN', index: true },
  groundTruth: String, isCorrect: Boolean, confidence: { type: Number, required: true }, maliciousProbability: Number,
  riskScore: { type: Number, min: 0, max: 100, required: true }, severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true, index: true },
  explanation: [{ feature: String, contribution: Number, value: Schema.Types.Mixed }], probabilities: Schema.Types.Mixed,
  modelVersion: String, modelAlgorithm: String, createdAt: { type: Date, default: Date.now, index: true }
});
detectionSchema.plugin(tenantPlugin);

const alertSchema = new Schema({
  detection: { type: Schema.Types.ObjectId, ref: 'Detection', required: true },
  environment: { type: String, enum: ['operational', 'benchmark', 'test'], default: 'operational', index: true },
  title: { type: String, required: true }, severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true, index: true },
  status: { type: String, enum: ['new', 'investigating', 'resolved', 'false_positive'], default: 'new', index: true },
  assignee: { type: Schema.Types.ObjectId, ref: 'User' }, notes: [{ body: String, author: { type: Schema.Types.ObjectId, ref: 'User' }, createdAt: { type: Date, default: Date.now } }],
  correlationKey: { type: String, index: true }, eventCount: { type: Number, default: 1 }, firstSeenAt: { type: Date, default: Date.now }, lastSeenAt: { type: Date, default: Date.now }
}, { timestamps: true });
alertSchema.plugin(tenantPlugin);

const incidentSchema = new Schema({
  title: { type: String, required: true }, summary: String,
  environment: { type: String, enum: ['operational', 'test'], default: 'operational', index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true },
  status: { type: String, enum: ['open', 'investigating', 'contained', 'resolved'], default: 'open' },
  alerts: [{ type: Schema.Types.ObjectId, ref: 'Alert' }], assignee: { type: Schema.Types.ObjectId, ref: 'User' },
  timeline: [{ action: String, note: String, user: { type: Schema.Types.ObjectId, ref: 'User' }, createdAt: { type: Date, default: Date.now } }]
}, { timestamps: true });
incidentSchema.plugin(tenantPlugin);

const modelVersionSchema = new Schema({
  name: { type: String, required: true }, version: { type: String, required: true }, algorithm: String, metrics: Schema.Types.Mixed,
  featureNames: [String], classes: [String], trainedAt: Date, dataset: String, trainingScope: String, sourceName: String, sourceUrl: String,
  researchGrade: Boolean, active: { type: Boolean, default: false }, artifactHash: String
}, { timestamps: true });

const settingSchema = new Schema({
  key: { type: String, required: true, index: true }, organizationName: String,
  maliciousThreshold: { type: Number, default: 0.5, min: 0, max: 1 },
  severityThresholds: { medium: { type: Number, default: 45 }, high: { type: Number, default: 70 }, critical: { type: Number, default: 88 } },
  alertGroupingMinutes: { type: Number, default: 10, min: 1, max: 1440 }
}, { timestamps: true });
settingSchema.plugin(tenantPlugin);
settingSchema.index({ organization: 1, key: 1 }, { unique: true });

const auditLogSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User' }, action: { type: String, required: true, index: true }, entityType: String, entityId: String,
  details: Schema.Types.Mixed, ip: String, createdAt: { type: Date, default: Date.now, index: true }
});
auditLogSchema.plugin(tenantPlugin);

const integrationSchema = new Schema({
  name: { type: String, required: true }, type: { type: String, enum: ['flow_forwarder', 'cicflowmeter', 'custom'], default: 'custom' },
  apiKeyHash: { type: String, required: true }, keyPrefix: String, enabled: { type: Boolean, default: true }, lastSeenAt: Date,
  createdBy: { type: Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
integrationSchema.plugin(tenantPlugin);

const benchmarkRunSchema = new Schema({
  status: { type: String, enum: ['running', 'completed', 'failed'], default: 'running', index: true }, sourceName: { type: String, default: 'CICIDS2017 Benchmark' },
  sourceUrl: String, datasetRecords: Number, recordsRequested: Number, recordsProcessed: { type: Number, default: 0 }, benignPredictions: { type: Number, default: 0 },
  maliciousPredictions: { type: Number, default: 0 }, correctPredictions: { type: Number, default: 0 }, binaryCorrectPredictions: { type: Number, default: 0 },
  accuracy: Number, binaryAccuracy: Number, attackDistribution: { type: Schema.Types.Mixed, default: {} }, groundTruthDistribution: { type: Schema.Types.Mixed, default: {} },
  modelVersion: String, modelAlgorithm: String, modelTrainingScope: String, startedAt: { type: Date, default: Date.now }, completedAt: Date, error: String,
  createdBy: { type: Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
benchmarkRunSchema.plugin(tenantPlugin);

export const Organization = model('Organization', organizationSchema);
export const User = model('User', userSchema);
export const Membership = model('Membership', membershipSchema);
export const TrafficEvent = model('TrafficEvent', trafficEventSchema);
export const Detection = model('Detection', detectionSchema);
export const Alert = model('Alert', alertSchema);
export const Incident = model('Incident', incidentSchema);
export const ModelVersion = model('ModelVersion', modelVersionSchema);
export const Setting = model('Setting', settingSchema);
export const AuditLog = model('AuditLog', auditLogSchema);
export const Integration = model('Integration', integrationSchema);
export const BenchmarkRun = model('BenchmarkRun', benchmarkRunSchema);
