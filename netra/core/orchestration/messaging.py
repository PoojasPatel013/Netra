import os
import json
import redis.asyncio as redis

REDIS_URL = os.getenv("NETRA_REDIS_URL", "redis://localhost:6379")

class NetraStream:
    def __init__(self, stream_key: str = "netra:events"):
        self.redis = None
        self.stream_key = stream_key

    async def connect(self):
        if not self.redis:
            self.redis = redis.from_url(REDIS_URL, decode_responses=True)

    async def publish_target(self, target: str, source: str = "ui", options: dict = {}):
        """Push a new scan target to the ingestion stream."""
        await self.connect()
        message = {
            "type": "target_added",
            "payload": json.dumps({"target": target, "source": source, "options": options})
        }
        await self.redis.xadd(self.stream_key, message)

    async def publish_raw_data(self, data: dict):
        """Push raw scan results for ML analysis."""
        await self.connect()
        # Publish to a different key for ML worker
        stream_key = "netra:data:raw"
        message = {
            "type": "raw_scan_result",
            "payload": json.dumps(data)
        }
        await self.redis.xadd(stream_key, message)

    async def consume_events(self, group: str, consumer: str):
        """Consume events from the stream (generator)."""
        await self.connect()
        # Ensure group exists
        try:
            await self.redis.xgroup_create(self.stream_key, group, mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise e

        while True:
            # Read new messages
            streams = await self.redis.xreadgroup(group, consumer, {self.stream_key: ">"}, count=1, block=5000)
            if not streams:
                continue

            for stream, messages in streams:
                for message_id, data in messages:
                    yield message_id, data
