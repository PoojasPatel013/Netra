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

from netra.api.models import Scan, ScanCreate, ScanRead, User
from netra.core.engine import NetraEngine
from netra.core.modules.cloud import CloudScanner
from netra.core.modules.acquisition import AcquisitionScanner
from netra.core.modules.iot import IoTScanner
from netra.core.modules.graphql import GraphQLScanner
from netra.core.modules.ruby_bridge import RubyScanner
from netra.core.modules.pentest import PentestEngine
from netra.integrations.defectdojo import DefectDojoClient
from netra.core.reporter import SARIFReporter
from netra.core.modules.recon import CTScanner
from netra.core.modules.secrets import SecretScanner
from netra.core.modules.api_fuzzer import ZombieScanner
from netra.core.orchestration.messaging import NetraStream
from redis import asyncio as aioredis
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from netra.core.auth import verify_password, get_password_hash, create_access_token, Token, UserInDB
from datetime import timedelta

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
from jose import jwt, JWTError
from netra.core.auth import SECRET_KEY, ALGORITHM

# Auth Dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check DB
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.post("/auth/register", response_model=Token)
async def register(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    # Check existing
    result = await session.execute(select(User).where(User.username == form_data.username))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pw = get_password_hash(form_data.password)
    user = User(username=form_data.username, hashed_password=hashed_pw)
    session.add(user)
    await session.commit()
    
    # Auto-login
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    # Fetch User
    result = await session.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "id": current_user.id}

# Catch-all for SPA (must be last)




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

async def sync_graph_results(scan_results: dict, target: str):
    """
    Syncs scan results to Neo4j Graph.
    """
    try:
        # 1. Create/Merge Target Domain Node
        query_target = "MERGE (d:Domain {name: $name}) SET d.last_seen = timestamp() RETURN d"
        db.cypher_query(query_target, {"name": target})
        
        # 2. Process Ports -> IP Address Nodes
        if "PortScanner" in scan_results:
             ports = scan_results["PortScanner"].get("open_ports", [])
             ip_addr = scan_results["PortScanner"].get("ip", "unknown")
             
             if ip_addr and ip_addr != "unknown":
                 # Create IP Node
                 query_ip = """
                 MATCH (d:Domain {name: $domain})
                 MERGE (i:IPAddress {address: $ip})
                 MERGE (d)-[:RESOLVES_TO]->(i)
                 """
                 db.cypher_query(query_ip, {"domain": target, "ip": ip_addr})
                 
                 # Create Service Nodes for Ports
                 for p in ports:
                     query_port = """
                     MATCH (i:IPAddress {address: $ip})
                     MERGE (s:Service {port: $port, protocol: 'tcp'})
                     MERGE (i)-[:EXPOSES]->(s)
                     """
                     db.cypher_query(query_port, {"ip": ip_addr, "port": p})

        # 3. Process Vulnerabilities -> Threat Nodes
        if "ThreatScanner" in scan_results:
            vulns = scan_results["ThreatScanner"].get("vulnerabilities", [])
            for v in vulns:
                query_vuln = """
                MATCH (d:Domain {name: $domain})
                MERGE (v:Vulnerability {name: $name, severity: $severity})
                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                """
                db.cypher_query(query_vuln, {"domain": target, "name": v.get("type", "Unknown"), "severity": v.get("severity", "Medium")})
        
        # Merge other vulnerabilities (IAMScanner, RubyScanner generic)
        for scanner_key in scan_results:
            if scanner_key in ["IAMScanner", "ResilienceScanner", "RubyScanner_banner_grabber"]:
                s_vulns = scan_results[scanner_key].get("vulnerabilities", [])
                for v in s_vulns:
                    query_v = """
                    MATCH (d:Domain {name: $domain})
                    MERGE (v:Vulnerability {name: $name, severity: $severity})
                    MERGE (d)-[:HAS_VULNERABILITY]->(v)
                    """
                    db.cypher_query(query_v, {"domain": target, "name": v.get("type", "Unknown"), "severity": v.get("severity", "Info")})
        
                db.cypher_query(query_acq, {"domain": target, "sub_name": acq["domain"]})

        # 5. ML Insight: Calculate Risk Score (Heuristic Algo)
        # Score = (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 0.5) + (OpenPorts * 1)
        risk_score = 0
        
        # Count Vulns
        if "ThreatScanner" in scan_results:
             vulns = scan_results["ThreatScanner"].get("vulnerabilities", [])
             for v in vulns:
                 sev = v.get("severity", "Info")
                 if sev == "Critical": risk_score += 10
                 elif sev == "High": risk_score += 5
                 elif sev == "Medium": risk_score += 2
                 elif sev == "Low": risk_score += 0.5
        
        # Count Ports
        if "PortScanner" in scan_results:
             ports = scan_results["PortScanner"].get("open_ports", [])
             risk_score += len(ports)
             
        # Normalize to 0-100 (Cap)
        risk_score = min(risk_score, 100)
        
        # Update Domain Node with ML Score
        query_score = "MATCH (d:Domain {name: $name}) SET d.risk_score = $score RETURN d"
        db.cypher_query(query_score, {"name": target, "score": risk_score})


    except Exception as e:
        print(f"Graph Sync Error: {e}")

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
            
            # Default Scanners (Ruby Bridge)
            # Port Scanning + Banner Grabbing
            v_engine.register_scanner(RubyScanner("banner_grabber.rb", name="PortScanner"))
            
            # Threat Intel (SPF/DMARC/Robots)
            v_engine.register_scanner(RubyScanner("threat_scan.rb", name="ThreatScanner"))

            # IAM & Session Analysis
            v_engine.register_scanner(RubyScanner("iam_scan.rb", name="IAMScanner"))

            # Resilience / Rate Limit
            if opts.get("resilience", False): # Only if resilience is toggled (assuming we use this option)
                v_engine.register_scanner(RubyScanner("resilience_scan.rb", name="ResilienceScanner"))
                v_engine.register_scanner(RubyBridge(script_name="dos_check.rb", name="DoSScanner"))
            else:
                # Default behavior if we want robust base scans? No, keep it opt-in for aggressive checks
                # Actually, main.py currently registers ResilienceScanner unconditionally in previous code.
                # Let's clean that logic up.
                pass
            
            # Re-inserting ResilienceScanner logic but conditional or default?
            # Original code lines 228-229 were unconditional.
            # I will modify them to be conditional or just add DoS next to it.
            # Given `dos_check` is aggressive, let's wrap BOTH in a check or just leave ResilienceScanner as is and add DoS.
            
            # CURRENT STATE: Line 229: v_engine.register_scanner(RubyScanner("resilience_scan.rb", name="ResilienceScanner"))
            # I will change it to:
            
            # Resilience / Rate Limit (Always on base check)
            v_engine.register_scanner(RubyScanner("resilience_scan.rb", name="ResilienceScanner"))
             
            # Aggressive DoS Checks (if requested)
            if opts.get("resilience", False) or opts.get("dos", False):
                 v_engine.register_scanner(RubyBridge(script_name="dos_check.rb", name="DoSScanner"))
            
            if opts.get("secrets", False):
                v_engine.register_scanner(SecretScanner())
                
            if opts.get("api_fuzz", False) or opts.get("zombie", False):
                v_engine.register_scanner(ZombieScanner())
                v_engine.register_scanner(RubyBridge(script_name="rce_scan.rb", name="RCEScanner"))
            
            if opts.get("cloud", False):
                v_engine.register_scanner(CloudScanner())
                
            if opts.get("iot", False):
                v_engine.register_scanner(IoTScanner())
                
            if opts.get("graphql", False):
                v_engine.register_scanner(GraphQLScanner())
                
                
            if opts.get("acquisitions", False):
                v_engine.register_scanner(AcquisitionScanner())
            
            # Auto Exploit (Polyglot)
            if opts.get("auto_exploit", False):
                 v_engine.register_scanner(PentestEngine())

            # Run with timeout to prevent zombies
            results = await asyncio.wait_for(v_engine.scan_target(scan.target), timeout=600)
            
            scan.results = results
            scan.results = results
            scan.status = "completed"
            
            # Sync to Graph (New Feature)
            await sync_graph_results(results, scan.target)
            
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
async def create_scan(scan_in: ScanCreate, background_tasks: BackgroundTasks, 
                      session: AsyncSession = Depends(get_session),
                      current_user: User = Depends(get_current_user)):
    scan = Scan(
        target=scan_in.target,
        scan_type=scan_in.scan_type,
        options=scan_in.options,
        status="pending",
        user_id=current_user.id
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
async def list_scans(offset: int = 0, limit: int = 100, 
                     session: AsyncSession = Depends(get_session),
                     current_user: User = Depends(get_current_user)):
    # Filter by user
    query = select(Scan).where(Scan.user_id == current_user.id).offset(offset).limit(limit)
    result = await session.execute(query)
    scans = result.scalars().all()
    return scans

@app.get("/scans/{scan_id}", response_model=ScanRead)
async def read_scan(scan_id: int, session: AsyncSession = Depends(get_session),
                    current_user: User = Depends(get_current_user)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
         raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    return scan

@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, session: AsyncSession = Depends(get_session),
                      current_user: User = Depends(get_current_user)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
         raise HTTPException(status_code=403, detail="Not authorized to delete this scan")
    
    session.delete(scan)
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

@app.get("/api/vulnerabilities")
async def get_all_vulnerabilities(limit: int = 100, session: AsyncSession = Depends(get_session)):
    """
    Aggregates vulnerabilities from all recent scans.
    """
    # In a real system, we might query Neo4j for (v:Vulnerability), but since we store report JSON in PG:
    result = await session.execute(select(Scan).order_by(Scan.timestamp.desc()).limit(50))
    scans = result.scalars().all()
    
    vulns = []
    for scan in scans:
        if not scan.results: continue
        
        # Helper to extract from scanner dicts
        for scanner_name, data in scan.results.items():
            # Check for standard 'vulnerabilities' list
            if isinstance(data, dict) and "vulnerabilities" in data:
                for v in data["vulnerabilities"]:
                    # Normalize
                    vulns.append({
                        "id": str(uuid.uuid4())[:8],
                        "scan_id": scan.id,
                        "target": scan.target,
                        "type": v.get("type", "Unknown"),
                        "severity": v.get("severity", "Info"),
                        "scanner": scanner_name,
                        "details": v.get("details", "") or v.get("description", ""),
                        "timestamp": scan.timestamp.isoformat() if scan.timestamp else ""
                    })
    
    # Return flattened list (client can filter)
    return vulns[:limit]
async def delete_asset(asset_id: int):
    """
    Deletes an asset (Domain or IP) by its Neo4j ID.
    """
    try:
        query = "MATCH (n) WHERE id(n) = $id DETACH DELETE n"
        db.cypher_query(query, {"id": asset_id})
        return {"ok": True, "deleted_id": asset_id}
    except Exception as e:
        print(f"Asset Delete Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete asset")

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

