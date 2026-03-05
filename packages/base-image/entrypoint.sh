#!/bin/bash
set -e

echo "========================================="
echo "Container IDS Agent Starting"
echo "========================================="

# Validate required environment variables
if [ -z "$AGENT_API_KEY" ]; then
    echo "WARNING: AGENT_API_KEY not set. Agent will not authenticate with platform."
    echo "Set AGENT_API_KEY environment variable to connect to the platform."
fi

if [ -z "$RABBITMQ_URL" ]; then
    echo "WARNING: RABBITMQ_URL not set. Using default: amqp://guest:guest@localhost:5672/"
fi

# Generate host ID if not exists
HOST_ID_FILE="/etc/container-ids/host_id"
if [ ! -f "$HOST_ID_FILE" ]; then
    # Generate unique host ID based on hostname and container ID
    HOST_ID=$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)
    echo "$HOST_ID" > "$HOST_ID_FILE"
    echo "Generated Host ID: $HOST_ID"
fi

export HOST_ID=$(cat "$HOST_ID_FILE")

# Display configuration
echo "Configuration:"
echo "  Host ID: $HOST_ID"
echo "  RabbitMQ URL: $(echo $RABBITMQ_URL | sed 's/:[^:@]*@/:***@/')"
echo "  Connection Service: $CONNECTION_SERVICE_ENABLED"
echo "  Connection Port: $CONNECTION_SERVICE_PORT"
echo "  Log Level: $AGENT_LOG_LEVEL"
echo "========================================="

# Start the agent in the background
echo "Starting Container IDS Agent..."
/opt/container-ids/agent \
    --config /etc/container-ids/agent.yaml \
    > /var/log/container-ids/agent.log 2>&1 &

AGENT_PID=$!
echo "Agent started with PID: $AGENT_PID"

# Function to handle shutdown
shutdown_handler() {
    echo ""
    echo "Received shutdown signal, stopping agent..."
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    echo "Agent stopped"
    exit 0
}

# Trap termination signals
trap shutdown_handler SIGTERM SIGINT

# Wait a moment for agent to start
sleep 2

# Check if agent is running
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "ERROR: Agent failed to start. Check logs at /var/log/container-ids/agent.log"
    cat /var/log/container-ids/agent.log
    exit 1
fi

echo "Agent is running and collecting telemetry"
echo "Connection service available at http://localhost:$CONNECTION_SERVICE_PORT"
echo "========================================="

# Execute the main container command
if [ $# -gt 0 ]; then
    echo "Executing application command: $@"
    exec "$@"
else
    echo "No command specified, keeping container alive..."
    # Keep container running and monitoring agent
    while kill -0 "$AGENT_PID" 2>/dev/null; do
        sleep 10
    done
    
    echo "Agent process died, exiting..."
    exit 1
fi