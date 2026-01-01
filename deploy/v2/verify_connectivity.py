import asyncio
import sys
from neomodel import config, db
from redis.asyncio import Redis

# Configuration matching docker-compose.yml
NEO4J_URL = "bolt://neo4j:netra-secret@localhost:7687"
REDIS_URL = "redis://localhost:6379"


async def check_redis():
    print(f"⏳ Connecting to Redis at {REDIS_URL}...")
    try:
        r = Redis.from_url(REDIS_URL)
        await r.ping()
        print("✅ Redis Connection Successful!")
        await r.close()
        return True
    except Exception as e:
        print(f"❌ Redis Connection Failed: {e}")
        return False


def check_neo4j():
    print(f"⏳ Connecting to Neo4j at {NEO4J_URL}...")
    config.DATABASE_URL = NEO4J_URL
    try:
        # Simple query to check connection
        results, meta = db.cypher_query("RETURN 'Netra v2 Online' as msg")
        print(f"✅ Neo4j Connection Successful! Message: {results[0][0]}")
        return True
    except Exception as e:
        print(f"❌ Neo4j Connection Failed: {e}")
        return False


async def main():
    print("🚀 Verifying Netra v2 Infrastructure Connectivity...")

    redis_ok = await check_redis()
    neo_ok = check_neo4j()

    if redis_ok and neo_ok:
        print("\n✨ All Systems Operational. You are ready to develop.")
        sys.exit(0)
    else:
        print(
            "\n⚠️  Some systems failed checks. Ensure containers are running (docker compose ps)."
        )
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
