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
        from netra.core.modules.network import PortScanner
        from netra.core.modules.http import HTTPScanner
        from netra.core.modules.threat import ThreatScanner
        from netra.core.modules.cloud import CloudScanner
        from netra.core.modules.go_bridge import GoScanner
        from netra.core.modules.rust_bridge import RustScanner

        payload = json.loads(event_data["payload"])
        event_type = event_data["type"]

        if event_type == "target_added":
            target = payload["target"]
            print(f"📥 Received Target: {target}")

            options = payload.get("options", {})
            print(f"⚙️ Scan Options: {options}")

            # Initialize Engine
            engine = NetraEngine()
            
            # Register Scanners
            # Standard Python Scanners (Always On for now, or could be toggled too)
            engine.register_scanner(PortScanner())
            engine.register_scanner(HTTPScanner())
            engine.register_scanner(ThreatScanner())
            engine.register_scanner(CloudScanner())
            
            # Polyglot Scanners - Conditional
            if options.get("TurboScan", True):
                print("🔹 Enabling TurboScan (Go)")
                engine.register_scanner(GoScanner())

            if options.get("LogCruncher", True):
                print("🔸 Enabling LogCruncher (Rust)")
                engine.register_scanner(RustScanner())

            # Run Scan
            results = await engine.scan_target(target)
            print(f"✅ Scan Complete for {target}. Results keys: {list(results.keys())}")
            
            # TODO: Save results to Neo4j/Postgres here
            
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
