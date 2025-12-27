import asyncio
import json
import os
from neomodel import config

from netra.core.orchestration.messaging import NetraStream
from netra.core.discovery.dns_resolver import DNSResolver

# from netra.core.analysis.ruby_bridge import RubyBridge # Will integrate in next step

# Configure Graph DB
NEO4J_URL = os.getenv("GRAPH_URL", "bolt://neo4j:netra-secret@localhost:7687")
config.DATABASE_URL = NEO4J_URL


async def process_event(event_data):
    """
    Router for different event types.
    """
    try:
        payload = json.loads(event_data["payload"])
        event_type = event_data["type"]

        if event_type == "target_added":
            target = payload["target"]
            print(f"📥 Received Target: {target}")

            # 1. Run DNS Discovery
            resolver = DNSResolver()
            await resolver.resolve(target)

            # 2. Todo: Trigger Ruby Scans

    except Exception as e:
        print(f"❌ Error processing event: {e}")


async def main():
    print("👷 Asset Discovery Worker Started...")
    stream = NetraStream()

    # Check connections
    try:
        # Simple connectivity check logic here if needed
        pass
    except Exception:
        pass

    # Consume Loop
    async for msg_id, data in stream.consume_events(
        group="workers", consumer="worker-1"
    ):
        print(f"Processing Msg ID: {msg_id}")
        await process_event(data)
        # Ack message (omitted for brevity, ideally stream.ack(msg_id))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Worker Stopped.")
