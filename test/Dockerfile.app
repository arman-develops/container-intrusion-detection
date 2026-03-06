# Test application - Simple Hello World API built on Container IDS base image
FROM armandevlops/container-ids-base:v1.0

# Install Node.js on Alpine
RUN apk add --no-cache nodejs npm

# Create app directory
WORKDIR /app

# Copy application files
COPY test/app/package.json test/app/server.js /app/

# Install dependencies
RUN npm install --production

# Expose application port
EXPOSE 3000

# The base image entrypoint will start the agent,
# then execute this command
CMD ["node", "server.js"]