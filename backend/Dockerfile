FROM node:22-alpine
WORKDIR /app
COPY backend/package*.json ./backend/
RUN cd backend && npm install --omit=dev
COPY backend ./backend
COPY frontend ./frontend
WORKDIR /app/backend
ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "src/server.js"]
