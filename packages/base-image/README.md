# Container IDS Base Image

This is the base Docker image that enterprises use to build their containerized applications with built-in security monitoring.

## Features

- ✅ **Automatic Telemetry Collection**: Monitors syscalls, network, filesystem, and processes
- ✅ **Real-time Streaming**: Sends events to the platform via RabbitMQ
- ✅ **Remote Access**: Built-in connection service for container management
- ✅ **Zero Configuration**: Works out of the box with sensible defaults
- ✅ **Lightweight**: Minimal overhead on application performance

## Quick Start

### 1. Build Your Application Image

```dockerfile
# Use Container IDS base image
FROM your-registry/container-ids-base:latest

# Install your application
COPY . /app
WORKDIR /app

# Install dependencies
RUN npm install  # or pip install, etc.

# Your application command
CMD ["npm", "start"]
```

### 2. Run with Required Environment Variables

```bash
docker run -d \
  -e AGENT_API_KEY="your-api-key-from-platform" \
  -e RABBITMQ_URL="amqp://user:pass@platform.example.com:5672/" \
  -p 3000:3000 \
  -p 8443:8443 \
  your-app:latest
```

### 3. Monitor on the Platform

Visit your Container IDS platform dashboard to see real-time monitoring and alerts.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AGENT_API_KEY` | **Yes** | - | API key from Container IDS platform |
| `RABBITMQ_URL` | **Yes** | - | RabbitMQ connection URL |
| `AGENT_LOG_LEVEL` | No | `info` | Log level: debug, info, warn, error |
| `CONNECTION_SERVICE_ENABLED` | No | `true` | Enable remote connection service |
| `CONNECTION_SERVICE_PORT` | No | `8443` | Port for connection service |

## Ports

- **8443**: Connection service for remote container access (HTTP API)

## Remote Access API

The base image includes a connection service that allows platform admins to remotely interact with containers.

### Endpoints

**Health Check** (no auth)
```bash
curl http://container:8443/health
```

**Container Info** (requires API key)
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://container:8443/info
```

**Execute Command**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"ps","args":["aux"],"timeout_seconds":10}' \
  http://container:8443/exec
```

**Get Logs**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path":"/var/log/app.log","lines":100}' \
  http://container:8443/logs
```

**File Operations**
```bash
# List directory
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path":"/app","operation":"list"}' \
  http://container:8443/files

# Read file
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path":"/app/config.json","operation":"read"}' \
  http://container:8443/files
```

## What Gets Monitored

### System Calls
- Process execution (execve, fork, clone)
- File operations (open, read, write, chmod)
- Network operations (socket, connect, bind)
- Privilege changes (setuid, setgid)

### Network Activity
- TCP/UDP connections
- Source/destination IPs and ports
- Data transfer volumes
- Connection patterns

### Filesystem Access
- File reads/writes
- Permission changes
- Access to sensitive paths (/etc, /root, /var)
- Credential file access

### Process Events
- Process creation/termination
- Parent-child relationships
- Capability changes
- Suspicious process patterns

## Security Considerations

1. **API Key Security**: Keep your `AGENT_API_KEY` secure. Rotate regularly.
2. **Network Isolation**: The connection service is for administrative access only.
3. **TLS**: Enable TLS in production by mounting certificates.
4. **Least Privilege**: The agent runs with necessary privileges for eBPF monitoring.

## Volume Mounts (Optional)

```bash
docker run -d \
  -v /path/to/agent.yaml:/etc/container-ids/agent.yaml \
  -v /path/to/certs:/etc/container-ids/certs \
  your-app:latest
```

## Docker Compose Example

```yaml
version: '3.8'

services:
  app:
    image: your-app:latest
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - AGENT_API_KEY=${AGENT_API_KEY}
      - RABBITMQ_URL=amqp://user:pass@rabbitmq:5672/
      - AGENT_LOG_LEVEL=info
    ports:
      - "3000:3000"
      - "8443:8443"
    depends_on:
      - rabbitmq

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"
```

## Building the Base Image

```bash
# From monorepo root
docker build -t container-ids-base:latest -f packages/base-image/Dockerfile .

# Tag for your registry
docker tag container-ids-base:latest your-registry/container-ids-base:latest

# Push to registry
docker push your-registry/container-ids-base:latest
```

## Troubleshooting

### Agent not starting
```bash
# Check agent logs
docker exec <container-id> cat /var/log/container-ids/agent.log
```

### Connection refused to platform
- Verify `RABBITMQ_URL` is correct
- Check network connectivity
- Ensure RabbitMQ is running

### High CPU usage
- Reduce monitoring scope in config
- Increase `batch_size` in agent.yaml
- Disable non-critical collectors

## Support

For issues or questions:
- Platform: https://platform.example.com/support
- Documentation: https://docs.example.com
- Email: support@example.com

## License

Proprietary - Licensed to enterprise customers only.