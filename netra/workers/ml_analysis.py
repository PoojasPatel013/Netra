import asyncio
import os
import json
import time
from netra.core.orchestration.messaging import NetraStream


async def process_ml_job(event_data):
    """
    Handles 'analysis' events.
    1. Load 'Heavy' Models (Mocked with sleep).
    2. Perform Classification.
    3. Update Graph.
    """
    try:
        payload = json.loads(event_data["payload"])
        target = payload.get("target")
        print(f"🧠 [ML-Worker] Analyzing: {target}")

        # 1. Loading Model (Simulation)
        # In real life: model = joblib.load('random_forest.pkl')
        time.sleep(1)  # Simulate CPU crunch

        # 2. Prediction
        risk_score = 0.85  # Mock prediction

        if risk_score > 0.7:
            print(f"⚠️  [ML-Worker] High Risk Detected! ({risk_score})")
            # Update Neo4j Graph here

    except Exception as e:
        print(f"❌ [ML-Worker] Error: {e}")


async def main():
    print("🤖 ML Analysis Worker (CPU Bound) Started...")
    # Listens to RAW data stream from Ingest Worker
    stream = NetraStream(stream_key="netra:data:raw")

    async for msg_id, data in stream.consume_events(group="ml_group", consumer="ml_1"):
        await process_ml_job(data)


if __name__ == "__main__":
    asyncio.run(main())
