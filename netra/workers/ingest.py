import asyncio
import os
import json
from netra.core.orchestration.messaging import NetraStream
from netra.core.discovery.dns_resolver import DNSResolver
from netra.core.analysis.ruby_bridge import RubyBridge

async def process_ingest_event(event_data, stream):
    """
    Handles 'ingest' events.
    1. Resolve DNS (Python Async).
    2. Run Ruby Scans (Process Bridge).
    3. Push Raw Data to 'raw' stream for ML Worker.
    """
    try:
        payload = json.loads(event_data['payload'])
        target = payload.get('target')
        print(f" [Ingest] Fast-Scanning: {target}")

        # 1. DNS Resolution
        resolver = DNSResolver()
        resolved = await resolver.resolve(target)
        
        # 2. Key Change: Execute Legacy Ruby Scans
        # This bridges the gap between old Ruby scripts and new Python architecture
        bridge = RubyBridge()
        # Example: Run 'dos_check.rb' against the target
        ruby_res = bridge.execute_script("dos_check.rb", target)
        print(f" [Ingest] Ruby Bridge Result: {ruby_res}")
        
        # 3. Push to ML Worker
        raw_result = {
            "target": target,
            "dns": resolved,
            "scan_data": {"ruby_scan": ruby_res}
        }
        
        await stream.publish_raw_data(raw_result)
        print(f" [Ingest] Pushed raw data to ML pipeline")

    except Exception as e:
        print(f"[Ingest] Error: {e}")

async def main():
    print("Ingestion Worker (I/O Bound) Started...")
    stream = NetraStream(stream_key="netra:events:ingest")
    
    async for msg_id, data in stream.consume_events(group="ingest_group", consumer="ingest_1"):
        await process_ingest_event(data, stream)

if __name__ == "__main__":
    asyncio.run(main())
