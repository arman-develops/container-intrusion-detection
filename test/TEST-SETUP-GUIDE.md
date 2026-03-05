# Local Testing Guide for Container IDS Base Image

This guide will help you test the complete Container IDS system locally before pushing to Docker Hub.

## Prerequisites

- Docker installed and running
- Docker Compose installed
- Your Docker Hub account ready

## Directory Structure

Create this structure in your project:

```
container-ids-platform/
├── packages/
│   ├── agent/              # (already exists)
│   └── base-image/         # (already exists)
├── test/
│   ├── app/
│   │   ├── package.json
│   │   └── server.js
│   ├── consumer.py
│   ├── Dockerfile.consumer
│   └── Dockerfile.app
├── docker-compose.test.yml
└── scripts/
    └── build-base-image.sh
```

## Step-by-Step Testing

### Step 1: Build the Base Image

```bash
# From project root
chmod +x scripts/build-base-image.sh
./scripts/build-base-image.sh

# Or manually:
docker build -t container-ids-base:latest -f packages/base-image/Dockerfile .
```

Verify the image:
```bash
docker images | grep container-ids-base
# Should show ~25-30MB image
```

### Step 2: Create Test Output Directory

```bash
mkdir -p test/output
```

### Step 3: Start the Test Environment

```bash
docker-compose -f docker-compose.test.yml up --build
```

You should see:
- ✓ RabbitMQ starting (management UI on http://localhost:15672)
- ✓ Telemetry consumer connecting
- ✓ Test app starting with agent

### Step 4: Verify Everything is Running

**Check containers:**
```bash
docker ps
```

You should see:
- `test-rabbitmq` - RabbitMQ broker
- `test-consumer` - Event consumer
- `test-app` - Your monitored application

**Check RabbitMQ Management UI:**
- Open http://localhost:15672
- Login: `admin` / `admin123`
- Check Exchanges → `container-ids`
- Check Queues → `telemetry-consumer`

**Check Agent Connection Service:**
```bash
curl http://localhost:8443/health
```

**Check Test Application:**
```bash
curl http://localhost:3000/
```

### Step 5: Generate Test Events

**Trigger filesystem events:**
```bash
curl -X POST http://localhost:3000/create-file \
  -H "Content-Type: application/json" \
  -d '{"content":"Hello from Container IDS test"}'
```

**Trigger network events:**
```bash
curl -X POST http://localhost:3000/network-test \
  -H "Content-Type: application/json" \
  -d '{"url":"https://api.github.com"}'
```

**Trigger process events:**
```bash
curl -X POST http://localhost:3000/process-test \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la /app"}'
```

### Step 6: View Collected Telemetry

**Watch live events in consumer logs:**
```bash
docker logs -f test-consumer
```

**Check dumped events file:**
```bash
# View all events
cat test/output/telemetry.jsonl

# View formatted
cat test/output/telemetry.jsonl | jq .

# Count events by type
cat test/output/telemetry.jsonl | jq -r '.event_type' | sort | uniq -c

# Filter syscall events
cat test/output/telemetry.jsonl | jq 'select(.event_type == "syscall")'

# Filter by container
cat test/output/telemetry.jsonl | jq 'select(.container_id | startswith("abc123"))'
```

### Step 7: Test Agent Connection Service

**Get container info:**
```bash
curl -H "Authorization: Bearer test-api-key-123" \
  http://localhost:8443/info | jq .
```

**Execute command in container:**
```bash
curl -X POST \
  -H "Authorization: Bearer test-api-key-123" \
  -H "Content-Type: application/json" \
  -d '{"command":"ps","args":["aux"]}' \
  http://localhost:8443/exec | jq .
```

**Get system metrics:**
```bash
curl -H "Authorization: Bearer test-api-key-123" \
  http://localhost:8443/metrics | jq .
```

**Read a file:**
```bash
curl -X POST \
  -H "Authorization: Bearer test-api-key-123" \
  -H "Content-Type: application/json" \
  -d '{"path":"/etc/os-release","operation":"read"}' \
  http://localhost:8443/files
```

### Step 8: Check Agent Logs

```bash
# View agent logs
docker exec test-app cat /var/log/container-ids/agent.log

# Follow agent logs
docker exec test-app tail -f /var/log/container-ids/agent.log
```

## Pushing to Docker Hub

Once testing is successful:

### Step 1: Login to Docker Hub

```bash
docker login
# Enter your Docker Hub username and password
```

### Step 2: Tag the Image

```bash
# Replace 'yourusername' with your Docker Hub username
docker tag container-ids-base:latest yourusername/container-ids-base:latest
docker tag container-ids-base:latest yourusername/container-ids-base:1.0.0
```

### Step 3: Push to Docker Hub

```bash
docker push yourusername/container-ids-base:latest
docker push yourusername/container-ids-base:1.0.0
```

### Step 4: Verify on Docker Hub

Visit https://hub.docker.com/r/yourusername/container-ids-base

### Step 5: Test Pulling

```bash
# On another machine or after removing local image
docker pull yourusername/container-ids-base:latest

# Run it
docker run -d \
  -e AGENT_API_KEY=test-key \
  -e RABBITMQ_URL=amqp://admin:admin123@YOUR_IP:5672/ \
  -p 3000:3000 \
  -p 8443:8443 \
  yourusername/container-ids-base:latest
```

## Cleanup

Stop and remove test environment:
```bash
docker-compose -f docker-compose.test.yml down -v
```

Remove test output:
```bash
rm -rf test/output/*
```

## Troubleshooting

### Agent not starting

```bash
docker exec test-app cat /var/log/container-ids/agent.log
```

### No events in output file

Check:
1. RabbitMQ is running: `docker logs test-rabbitmq`
2. Consumer is connected: `docker logs test-consumer`
3. Agent is publishing: `docker exec test-app cat /var/log/container-ids/agent.log`

### Connection refused

- Ensure all services are healthy: `docker-compose ps`
- Check networks: `docker network ls`
- Verify RabbitMQ: http://localhost:15672

### Test app not responding

```bash
docker logs test-app
```

## What You Should See

✅ **Agent starting** with host ID and config
✅ **RabbitMQ** receiving messages
✅ **Consumer** dumping events to file
✅ **Test app** responding to HTTP requests
✅ **Connection service** accepting authenticated requests
✅ **Events file** growing with telemetry data

## Next Steps

After successful local testing:
1. Push base image to Docker Hub
2. Update documentation with your Docker Hub username
3. Build the platform backend (FastAPI + PostgreSQL)
4. Build the web portal (Next.js)
5. Deploy to production!

## Example Output

When working correctly, `test/output/telemetry.jsonl` should contain entries like:

```json
{"event_id":"abc-123","event_type":"syscall","timestamp":"2024-01-27T10:30:00Z","host_id":"host-001","container_id":"container-abc","image_name":"test-app:latest","payload":{"name":"execve","pid":1234,"uid":0}}
{"event_id":"def-456","event_type":"network","timestamp":"2024-01-27T10:30:01Z","host_id":"host-001","container_id":"container-abc","image_name":"test-app:latest","payload":{"operation":"connect","dest_ip":"8.8.8.8","dest_port":443}}
```

Good luck with testing! 🚀