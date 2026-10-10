import 'dotenv/config';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { Membership } from './models/index.js';
import { Server as SocketServer } from 'socket.io';
import { connectDatabase } from './config/db.js';
import apiRouter from './routes/api.js';

if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');
if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is required');

const app = express();
const server = http.createServer(app);
const io = new SocketServer(server, { cors: { origin: process.env.FRONTEND_ORIGIN || true } });
io.use(async (socket, next) => {
  try {
    const bearer = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, '');
    const organizationId = socket.handshake.auth?.organizationId;
    if (!bearer || !organizationId) return next(new Error('Authentication and organization are required'));
    const payload = jwt.verify(bearer, process.env.JWT_SECRET);
    const membership = await Membership.findOne({ user: payload.sub, organization: organizationId, status: 'active' });
    if (!membership) return next(new Error('Organization access denied'));
    socket.user = payload;
    socket.organizationId = String(organizationId);
    next();
  } catch {
    next(new Error('Invalid or expired session'));
  }
});
app.set('io', io);

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || true }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use('/api', apiRouter);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(__dirname, '../../frontend/public');
app.use(express.static(frontendDir));
app.use((_req, res) => res.sendFile(path.join(frontendDir, 'index.html')));

io.on('connection', socket => { socket.join(`org:${socket.organizationId}`); socket.emit('system:connected', { at: new Date().toISOString(), organizationId: socket.organizationId }); });

const port = Number(process.env.PORT || 4000);
await connectDatabase(process.env.MONGODB_URI);
server.listen(port, () => console.log(`Mabeli Sentinel running on http://localhost:${port}`));
