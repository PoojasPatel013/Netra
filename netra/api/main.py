import asyncio
import os
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlmodel import SQLModel, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from netra.api.models import Scan, ScanCreate, ScanRead
from netra.core.engine import NetraEngine
from netra.core.modules.network import PortScanner
from netra.core.modules.http import HTTPScanner
from netra.core.modules.cloud import CloudScanner
from netra.core.modules.iot import IoTScanner
from netra.core.modules.graphql import GraphQLScanner
from netra.core.modules.pentest import PentestEngine
from netra.integrations.defectdojo import DefectDojoClient
from netra.core.reporter import SARIFReporter
from netra.core.modules.recon import CTScanner
from netra.core.modules.secrets import SecretScanner
from netra.core.modules.api_fuzzer import APIScanner
from netra.core.orchestration.messaging import NetraStream
from redis import asyncio as aioredis
from pydantic import BaseModel

# Database Setup
# Use SQLite for local development default, Postgres for Docker
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///netra.db")
REDIS_URL = os.getenv("REDIS_URL")

class ScanRequest(BaseModel):
    target: str
    options: dict = {}

engine = create_async_engine(DATABASE_URL, echo=True, future=True)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session():
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session

app = FastAPI(title="Netra API", version="0.1.0")

# Setup Static Files
# Serve from 'netra/static' directly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(os.path.dirname(BASE_DIR), "static")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

from fastapi.responses import FileResponse

# Catch-all for SPA (must be last)
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    # Allow API routes to pass through (though they should be matched before this if defined above)
    if full_path.startswith("api") or full_path.startswith("scans") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
        raise HTTPException(status_code=404, detail="Not Found")
    
    # Serve index.html for everything else
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "Static UI not found. Ensure netra/static/index.html exists."}



@app.post("/api/scan")
async def trigger_v2_scan(request: ScanRequest):
    """
    v2 Endpoint: Pushes target to Redis Stream for Distributed Scanning.
    """
    try:
        # Connect to the Ingestion Stream
        stream = NetraStream(stream_key="netra:events:ingest")
        await stream.publish_target(request.target, source="api", options=request.options)
        return {"status": "queued", "target": request.target, "message": "Dispatched to Ingestion Worker"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def on_startup():
    print(f"DEBUG: BASE_DIR={BASE_DIR}")
    print(f"DEBUG: STATIC_DIR={STATIC_DIR}")
    print(f"DEBUG: STATIC_DIR={STATIC_DIR}")
    if os.path.exists(STATIC_DIR):
        print(f"DEBUG: STATIC_DIR exists. Contents: {os.listdir(STATIC_DIR)}")
    else:
        print(f"DEBUG: STATIC_DIR DOES NOT EXIST at {STATIC_DIR}")
        
    retries = 5
    wait = 2
    for i in range(retries):
        try:
            await init_db()
            print("Database connected successfully.")
            return
        except Exception as e:
            print(f"Database connection failed ({i+1}/{retries}): {e}")
            if i < retries - 1:
                await asyncio.sleep(wait)
                wait *= 2  # Exponential backoff
            else:
                raise e

@app.get("/debug/fs")
async def debug_fs():
    """Temporary debug endpoint to inspect container filesystem"""
    try:
        debug_info = {
            "cwd": os.getcwd(),
            "base_dir": BASE_DIR,
            "static_dir": STATIC_DIR,
            "dist_dir": DIST_DIR,
            "dist_exists": os.path.exists(DIST_DIR),
            "dist_contents": os.listdir(DIST_DIR) if os.path.exists(DIST_DIR) else [],
            "static_contents": os.listdir(STATIC_DIR) if os.path.exists(STATIC_DIR) else [],
            "app_netra_contents": os.listdir("/app/netra") if os.path.exists("/app/netra") else "Not found",
        }
        return debug_info
    except Exception as e:
        return {"error": str(e)}

async def run_scan_task(scan_id: int):
    # Create a new session for this task
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
            
        scan.status = "running"
        session.add(scan)
        await session.commit()
        
        try:
            # Run Netra Engine
            v_engine = NetraEngine()
            
            # Configure Scanners (Based on Options)
            opts = scan.options or {}
            
            # 1. CT Recon (Always good to have if enabled, or default)
            # Check if toggled or just run it
            if opts.get("recon", True): # Default to true
                 v_engine.register_scanner(CTScanner())
            
            # Default Scanners
            v_engine.register_scanner(HTTPScanner())
            
            if opts.get("secrets", False):
                v_engine.register_scanner(SecretScanner())
                
            if opts.get("api_fuzz", False):
                v_engine.register_scanner(APIScanner())
            
            port_list = None
            if opts.get("ports"):
                 # Handle comma separated string or list
                p_arg = opts.get("ports")
                if isinstance(p_arg, str):
                    port_list = [int(p) for p in p_arg.split(",")]
                elif isinstance(p_arg, list):
                    port_list = p_arg
            
            v_engine.register_scanner(PortScanner(ports=port_list))
            
            if opts.get("cloud", False):
                v_engine.register_scanner(CloudScanner())
                
            if opts.get("iot", False):
                v_engine.register_scanner(IoTScanner())
                
            if opts.get("graphql", False):
                v_engine.register_scanner(GraphQLScanner())
            
            # Auto Exploit (Polyglot)
            if opts.get("auto_exploit", False):
                 v_engine.register_scanner(PentestEngine())

            # Run with timeout to prevent zombies
            results = await asyncio.wait_for(v_engine.scan_target(scan.target), timeout=600)
            
            scan.results = results
            scan.status = "completed"
            
            # Post-Scan Actions: DefectDojo Import
            if opts.get("defect_dojo_url") and opts.get("defect_dojo_key") and opts.get("engagement_id"):
                try:
                    logger.info("Triggering DefectDojo Import...")
                    dd_client = DefectDojoClient(opts.get("defect_dojo_url"), opts.get("defect_dojo_key"))
                    await dd_client.import_scan(results, int(opts.get("engagement_id")))
                except Exception as dd_e:
                    logger.error(f"DefectDojo Integration Failed: {dd_e}")
                    # Don't fail the scan status, just log
            
        except asyncio.TimeoutError:
             scan.status = "failed"
             scan.results = {"error": "Scan timed out (300s limit)"}
        except Exception as e:
            print(f"Scan Task Error: {e}")
            scan.status = "failed"
            scan.results = {"error": str(e)}
        finally:
            session.add(scan)
            await session.commit()

@app.post("/scans", response_model=ScanRead)
async def create_scan(scan_in: ScanCreate, background_tasks: BackgroundTasks, session: AsyncSession = Depends(get_session)):
    scan = Scan(
        target=scan_in.target,
        scan_type=scan_in.scan_type,
        options=scan_in.options,
        status="pending"
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    
    # Distributed (Drone) Mode vs Local
    if REDIS_URL:
        try:
            redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
            await redis.rpush("netra_tasks", str(scan.id))
            print(f"Dispatched Scan {scan.id} to Drone Grid")
            await redis.close()
        except Exception as e:
            print(f"Redis dispatch failed: {e}. Falling back to local.")
            background_tasks.add_task(run_scan_task, scan.id)
    else:
        background_tasks.add_task(run_scan_task, scan.id)
        
    return scan

@app.get("/scans", response_model=List[ScanRead])
async def list_scans(offset: int = 0, limit: int = 100, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Scan).offset(offset).limit(limit))
    scans = result.scalars().all()
    return scans

@app.get("/scans/{scan_id}", response_model=ScanRead)
async def read_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await session.delete(scan)
    await session.commit()
    return {"ok": True}

    
    if not scan.results:
        return {"error": "Scan has no results yet"}

    reporter = SARIFReporter()
    sarif_data = reporter.convert_scan_results(scan.results, scan.target)
    
    return sarif_data

# Graph & Asset Endpoints (Real Data Wiring)
from neomodel import config, db

# Initialize Neo4j (Lazy connection)
# Ensure NEO4J_URL is suitable for neomodel (bolt://user:pass@host:port)
config.DATABASE_URL = os.getenv("NEO4J_URL", "bolt://neo4j:netra-secret@neo4j:7687")

@app.get("/api/graph")
async def get_graph_data():
    """
    Returns the Knowledge Graph (Nodes & Edges) for visualization.
    """
    try:
        # Fetch generic graph data (Limit to avoid exploding the UI)
        query = "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 200"
        results, meta = db.cypher_query(query)
        
        nodes = {}
        links = []
        
        for row in results:
            source_node = row[0]
            rel = row[1]
            target_node = row[2]
            
            # Helper to deduplicate nodes
            def process_node(node):
                labels = list(node.labels)
                node_id = str(node.id)
                if node_id not in nodes:
                    # Try to find a meaningful label/name
                    label = node.get('name') or node.get('address') or node.get('resource_id') or node.get('fingerprint') or "Unknown"
                    nodes[node_id] = {
                        "id": node_id,
                        "group": labels[0] if labels else "Node",
                        "label": label,
                        "properties": dict(node)
                    }
                return node_id

            s_id = process_node(source_node)
            t_id = process_node(target_node)
            
            links.append({
                "source": s_id,
                "target": t_id,
                "type": rel.type
            })
            
        return {
            "nodes": list(nodes.values()),
            "links": links
        }
    except Exception as e:
        print(f"Graph Query Error: {e}")
        # Return empty structure on failure to prevent UI crash
        return {"nodes": [], "links": []}

@app.get("/api/assets")
async def get_assets_inventory():
    """
    Returns a flattened inventory of all discovered assets.
    """
    try:
        # Fetch Domains
        query_domains = "MATCH (d:Domain) RETURN d"
        domains, _ = db.cypher_query(query_domains)
        
        # Fetch IPs
        query_ips = "MATCH (i:IPAddress) RETURN i"
        ips, _ = db.cypher_query(query_ips)
        
        assets = []
        
        for row in domains:
            d = row[0]
            assets.append({
                "id": d.id,
                "name": d['name'],
                "type": "Domain",
                "details": f"Registrar: {d.get('registrar', 'N/A')}",
                "status": "active" # Placeholder
            })
            
        for row in ips:
            i = row[0]
            assets.append({
                "id": i.id,
                "name": i['address'],
                "type": "IP Address",
                "details": f"Version: {i.get('version', 'IPv4')}",
                "status": "active"
            })
            
        return assets
    except Exception as e:
        print(f"Asset Query Error: {e}")
        return []

@app.get("/api/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    """
    Returns aggregated system stats for the dashboard.
    """
    try:
        # 1. Count Scans
        result = await session.execute(select(Scan))
        scans = result.scalars().all()
        scan_count = len(scans)
        
        # 2. Count Assets (Neo4j)
        # Use a fast count query
        nodes_result, _ = db.cypher_query("MATCH (n) RETURN count(n)")
        asset_count = nodes_result[0][0]
        
        # 3. Count Vulns (Approximate from Scans for now, or specific node label)
        # For now, let's sum vulns found in recent scans if stored, or just placeholder '0' until VulnModel is strict.
        # Simple approach: sum scan.results['ThreatScanner']['vulnerabilities'].length
        vuln_count = 0
        for s in scans:
            if s.results and isinstance(s.results, dict):
                 threats = s.results.get('ThreatScanner', {}).get('vulnerabilities', [])
                 vuln_count += len(threats)

        return {
            "scans": scan_count,
            "assets": asset_count,
            "vulns": vuln_count
        }
    except Exception as e:
        print(f"Stats Error: {e}")
        return {"scans": 0, "assets": 0, "vulns": 0}
