# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --no-audit --no-fund

# Copy source code
COPY . .

# Set environment variable for build
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

# Build the application
RUN npm run build

# Production stage. Keep only Alpine, the Node binary, and the traced Next.js
# output; npm, corepack, headers, and the full Node distribution are build-only.
FROM alpine:3.23 AS runner

WORKDIR /app

ENV NODE_ENV=production

# Node's Alpine binary only needs the C++ runtime in addition to Alpine.
RUN apk add --no-cache libstdc++ \
    && addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 --ingroup nodejs nextjs

COPY --from=builder /usr/local/bin/node /usr/local/bin/node

# Copy necessary files from builder
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
