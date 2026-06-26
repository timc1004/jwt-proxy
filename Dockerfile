# ─── Build stage ──────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ─── Runtime stage ───────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Security: run as non-root
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

COPY --from=builder /app/node_modules ./node_modules
COPY server.js ./

# Drop privileges
USER appuser

EXPOSE 8080

ENV PORT=8080
ENV TARGET_HOST=http://localhost:3000
ENV CLOUDFLARE_JWKS_URL=""
ENV CLOUDFLARE_AUD_TOKEN=""

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

CMD ["node", "server.js"]
