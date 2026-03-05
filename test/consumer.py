#!/usr/bin/env python3
"""
Simple RabbitMQ consumer that dumps telemetry events to a file
"""
import os
import sys
import json
import time
from datetime import datetime
import pika

RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://admin:admin123@rabbitmq:5672/')
OUTPUT_FILE = os.getenv('OUTPUT_FILE', '/data/telemetry.jsonl')
EXCHANGE = 'container-ids'
ROUTING_KEY = 'telemetry'

def setup_rabbitmq():
    """Connect to RabbitMQ and setup exchange/queue"""
    max_retries = 30
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            print(f"Connecting to RabbitMQ (attempt {attempt + 1}/{max_retries})...")
            params = pika.URLParameters(RABBITMQ_URL)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            
            # Declare exchange
            channel.exchange_declare(
                exchange=EXCHANGE,
                exchange_type='topic',
                durable=True
            )
            
            # Create queue
            queue_name = 'telemetry-consumer'
            channel.queue_declare(queue=queue_name, durable=True)
            
            # Bind queue to exchange
            channel.queue_bind(
                exchange=EXCHANGE,
                queue=queue_name,
                routing_key=ROUTING_KEY
            )
            
            print(f"✓ Connected to RabbitMQ")
            print(f"✓ Exchange: {EXCHANGE}")
            print(f"✓ Queue: {queue_name}")
            print(f"✓ Routing Key: {ROUTING_KEY}")
            print(f"✓ Output: {OUTPUT_FILE}")
            print("-" * 60)
            
            return connection, channel, queue_name
            
        except Exception as e:
            print(f"Connection failed: {e}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Max retries reached. Exiting.")
                sys.exit(1)

def callback(ch, method, properties, body):
    """Process incoming telemetry event"""
    try:
        # Parse event
        event = json.loads(body)
        
        # Add processing metadata
        event['_processed_at'] = datetime.utcnow().isoformat()
        event['_message_id'] = properties.message_id
        
        # Pretty print to console
        print(f"\n{'='*60}")
        print(f"Event ID: {event.get('event_id', 'N/A')}")
        print(f"Type: {event.get('event_type', 'N/A')}")
        print(f"Container: {event.get('container_id', 'N/A')[:12]}")
        print(f"Timestamp: {event.get('timestamp', 'N/A')}")
        print(f"Payload: {json.dumps(event.get('payload', {}), indent=2)}")
        print(f"{'='*60}")
        
        # Append to file (JSONL format - one JSON per line)
        with open(OUTPUT_FILE, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        # Acknowledge message
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    except Exception as e:
        print(f"Error processing message: {e}")
        # Reject and requeue
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

def main():
    """Main consumer loop"""
    print("=" * 60)
    print("Container IDS Telemetry Consumer")
    print("=" * 60)
    
    # Setup RabbitMQ
    connection, channel, queue_name = setup_rabbitmq()
    
    # Setup consumer
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(
        queue=queue_name,
        on_message_callback=callback
    )
    
    print("✓ Consumer ready. Waiting for telemetry events...")
    print("✓ Press CTRL+C to stop")
    print("=" * 60)
    
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        print("\nStopping consumer...")
        channel.stop_consuming()
        connection.close()
        print("✓ Consumer stopped")

if __name__ == '__main__':
    main()