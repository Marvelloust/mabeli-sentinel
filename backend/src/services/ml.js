import axios from 'axios';

const client = axios.create({
  baseURL: process.env.ML_SERVICE_URL || 'http://localhost:8000',
  timeout: 120000
});

export async function mlHealth() {
  const { data } = await client.get('/health');
  return data;
}

export async function modelInfo() {
  const { data } = await client.get('/model');
  return data;
}

export async function bootstrapStatus() {
  const { data } = await client.get('/bootstrap/status');
  return data;
}

export async function requestModelUpgrade() {
  const { data } = await client.post('/bootstrap/upgrade');
  return data;
}

export async function benchmarkInfo() {
  const { data } = await client.get('/benchmark/info');
  return data;
}

export async function benchmarkSample(limit = 100, seed = 42) {
  const { data } = await client.get('/benchmark/sample', { params: { limit, seed } });
  return data;
}

export async function predict(features) {
  const { data } = await client.post('/predict', { features });
  return data;
}

export async function predictBatch(records) {
  const { data } = await client.post('/predict/batch', { records });
  return data;
}

export async function trainModel(payload) {
  const { data } = await client.post('/train', payload, { timeout: 60 * 60 * 1000 });
  return data;
}
