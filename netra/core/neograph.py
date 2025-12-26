
from neo4j import GraphDatabase
import os
import logging

logger = logging.getLogger("netra.core.neograph")

class NeoGraph:
    def __init__(self):
        # Default fallback for Docker Compose
        self.uri = os.getenv("NEO4J_URL", "bolt://neo4j:7687")
        # Parse auth from URI if possible, or use defaults
        # Expected format: bolt://user:pass@host:port
        # But neo4j driver expects auth as tuple
        
        # Simplified parsing or assuming env vars for auth if separate
        # Docker Compose usually sets NEO4J_AUTH for the server, but client needs it too.
        # Let's support standard bolt://user:pass@host:port connection string which driver handles?
        # Actually standard driver: GraphDatabase.driver(uri, auth=(user, password))
        
        # Let's parse the user/pass from the URL if present
        self.driver = None
        try:
            # If URL has user:pass@host, extract it or pass as is? 
            # Modern neo4j driver 5.x supports connection URI directly with auth?
            # Let's try explicit auth extraction for safety
            
            auth = None
            uri_to_use = self.uri
            
            if "@" in self.uri:
                # Naive parse: bolt://user:pass@host:port
                # Split schema
                schema, rest = self.uri.split("://")
                creds, host = rest.split("@")
                if ":" in creds:
                    u, p = creds.split(":")
                    auth = (u, p)
                else:
                    auth = (creds, "")
                
                uri_to_use = f"{schema}://{host}"
            
            self.driver = GraphDatabase.driver(uri_to_use, auth=auth)
            logger.info(f"Neo4j Driver initialized for {uri_to_use}")
            
        except Exception as e:
            logger.error(f"Failed to init Neo4j driver: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def cypher_query(self, query, params=None):
        if not self.driver:
            return [], None
            
        try:
            with self.driver.session() as session:
                result = session.run(query, params or {})
                # Eagerly consume result
                records = [record for record in result]
                meta = result.consume()
                return records, meta
        except Exception as e:
            logger.error(f"Cypher Query Failed: {e}")
            return [], None
