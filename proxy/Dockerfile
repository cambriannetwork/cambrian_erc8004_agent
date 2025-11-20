FROM node:18-slim

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev --no-audit --no-fund

# Copy application code
COPY server.js .

# Expose port
EXPOSE 8090

# Set environment variables
ENV PORT=8090
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8090/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start the proxy server
CMD ["node", "server.js"]
