# Base Node Image
FROM node:20-bullseye-slim AS base

# Install OS dependencies required for scanning (nmap, whois, traceroute)
# We use standard bullseye-slim to keep the footprint small (~250MB)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app
# Skip Chromium download during npm install to keep the image strictly minimal
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_SKIP_DOWNLOAD=true
# Install dependencies based on the preferred package manager
COPY package.json package-lock.json ./
RUN npm ci


# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Next.js telemetry disable
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# We need full access to nmap capabilities (NET_RAW) for deep scans. 
# In Kubernetes, this container should run with securityContext.capabilities.add: ["NET_RAW"]
# However, if running as non-root, nmap stealth flags drop. We'll run as root for the scanner needs, 
# or administrators can adjust as needed. By default, keeping standard runner.

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built assets
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT=3000

# server.js is created by next build from the standalone output
CMD ["node", "server.js"]
