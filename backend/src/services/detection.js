import { Alert, Detection, Setting, TrafficEvent } from '../models/index.js';
import { predict } from './ml.js';
import { currentTenantId, tenantSettingKey } from './tenant-context.js';

function scoreRisk(prediction, attackType, confidence) {
  if (prediction === 'benign') return Math.max(1, Math.round((1 - confidence) * 25));
  const attackWeights = {
    DDoS: 98,
    'DoS Hulk': 91,
    'DoS GoldenEye': 88,
    'DoS slowloris': 86,
    'DoS Slowhttptest': 84,
    Heartbleed: 100,
    Infiltration: 96,
    PortScan: 73,
    Bot: 82,
    'FTP-Patator': 77,
    'SSH-Patator': 79,
    'Web Attack Brute Force': 80,
    'Web Attack XSS': 86,
    'Web Attack Sql Injection': 94,
    WebAttack: 88,
    BruteForce: 79,
    DoS: 89
  };
  const base = attackWeights[attackType] || 75;
  return Math.max(0, Math.min(100, Math.round(base * 0.65 + confidence * 100 * 0.35)));
}

function severityFor(score, thresholds) {
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  return 'low';
}

function normalizeLabel(value) {
  if (!value) return undefined;
  const s = String(value).replaceAll('�', '-').replaceAll('–', '-').replace(/\s+/g, ' ').trim();
  if (s.toUpperCase() === 'BENIGN') return 'BENIGN';
  return s.replace('Web Attack - ', 'Web Attack ');
}

export async function processTraffic({ features, meta = {}, io }) {
  const started = Date.now();
  const organizationId = currentTenantId();
  if (!organizationId) throw new Error('Organization context is required for traffic processing');
  const settings = await Setting.findOneAndUpdate(
    { key: tenantSettingKey() },
    { $setOnInsert: { key: tenantSettingKey() } },
    { upsert: true, new: true }
  );
  const environment = ['benchmark', 'test'].includes(meta.environment) ? meta.environment : 'operational';
  const traffic = await TrafficEvent.create({
    organization: organizationId,
    source: meta.source || (environment === 'benchmark' ? 'benchmark' : environment === 'test' ? 'test' : 'manual'),
    environment,
    sourceName: meta.sourceName || (environment === 'benchmark' ? 'CICIDS2017 Benchmark' : environment === 'test' ? 'Sentinel Test Kit' : 'Analyst input'),
    sourceIp: meta.sourceIp,
    destinationIp: meta.destinationIp,
    sourcePort: meta.sourcePort,
    destinationPort: meta.destinationPort,
    protocol: meta.protocol,
    rawLabel: normalizeLabel(meta.rawLabel),
    benchmarkRunId: meta.benchmarkRunId,
    features
  });

  try {
    const result = await predict(features);
    const prediction = result.prediction === 'malicious' ? 'malicious' : 'benign';
    const confidence = Number(result.confidence || 0);
    const attackType = normalizeLabel(result.attack_type) || (prediction === 'benign' ? 'BENIGN' : 'Unknown');
    const groundTruth = normalizeLabel(meta.rawLabel);
    const isCorrect = groundTruth ? attackType === groundTruth : undefined;
    const riskScore = scoreRisk(prediction, attackType, confidence);
    const severity = severityFor(riskScore, settings.severityThresholds);
    traffic.processingMs = Date.now() - started;
    await traffic.save();

    const detection = await Detection.create({
      organization: organizationId,
      trafficEvent: traffic._id,
      environment,
      prediction,
      attackType,
      groundTruth,
      isCorrect,
      confidence,
      maliciousProbability: result.malicious_probability,
      riskScore,
      severity,
      explanation: result.explanation || [],
      probabilities: result.probabilities || {},
      modelVersion: result.model_version,
      modelAlgorithm: result.model_algorithm
    });

    let alert = null;
    const alertsEnabled = ['operational', 'test'].includes(environment) && meta.generateAlerts !== false;
    if (alertsEnabled && prediction === 'malicious' && (result.malicious_probability ?? confidence) >= settings.maliciousThreshold) {
      const groupingMs = settings.alertGroupingMinutes * 60 * 1000;
      const correlationKey = [detection.attackType, meta.sourceIp || 'unknown', meta.destinationIp || 'unknown'].join('|');
      alert = await Alert.findOne({
        environment,
        correlationKey,
        status: { $in: ['new', 'investigating'] },
        lastSeenAt: { $gte: new Date(Date.now() - groupingMs) }
      }).sort({ lastSeenAt: -1 });

      if (alert) {
        alert.eventCount += 1;
        alert.lastSeenAt = new Date();
        if (['critical', 'high', 'medium', 'low'].indexOf(severity) < ['critical', 'high', 'medium', 'low'].indexOf(alert.severity)) {
          alert.severity = severity;
        }
        await alert.save();
      } else {
        alert = await Alert.create({
          organization: organizationId,
          detection: detection._id,
          environment,
          title: `${detection.attackType} activity detected`,
          severity,
          correlationKey,
          firstSeenAt: new Date(),
          lastSeenAt: new Date()
        });
      }
    }

    io?.to(`org:${organizationId}`).emit('detection:new', { detection, traffic });
    if (alert) io?.to(`org:${organizationId}`).emit('alert:update', alert);
    return { traffic, detection, alert };
  } catch (error) {
    traffic.status = 'failed';
    traffic.error = error.response?.data?.detail || error.message;
    traffic.processingMs = Date.now() - started;
    await traffic.save();
    throw error;
  }
}
