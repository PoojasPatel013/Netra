import asyncio
import os
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
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
from netra.ml.zombie_hunter import ZombieHunter
from netra.core.orchestration.messaging import NetraStream
from redis import asyncio as aioredis
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from netra.core.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    Token,
)
from datetime import timedelta

# Database Setup
# Use SQLite for local development default, Postgres for Docker
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///netra.db")
# Ensure we use async driver for Postgres
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

REDIS_URL = os.getenv("REDIS_URL")


class ScanRequest(BaseModel):
    target: str
    options: dict = {}


# MinIO Setup (Data Lake)
# MinIO Setup (Data Lake)
MINIO_URL = os.getenv("MINIO_URL", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin_change_me")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin_change_me")
MAX_MODEL_SIZE_MB = 100

minio_client = None
try:
    from minio import Minio

    minio_client = Minio(
        MINIO_URL,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )
except ImportError:
    print(
        "WARNING: 'minio' library not found. Data Lake disabled. Run 'docker compose up --build'."
    )
except Exception as e:
    print(f"MinIO Init Failed: {e}")

# Global ML Model (Inference)
from netra.core.neograph import NeoGraph

# Global ML Model (Inference)
ML_MODEL = None
import pickle
import io

engine = create_async_engine(DATABASE_URL, echo=True, future=True)
db = None  # Global Neo4j Connection


async def init_db():
    retries = 5
    while retries > 0:
        try:
            print(
                f"DEBUG: init_db called. Tables in metadata: {list(SQLModel.metadata.tables.keys())}"
            )
            async with engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)
            print("DB Connected & Initialized")
            break
        except Exception as e:
            retries -= 1
            print(f"DB Connection Failed ({e}). Retrying in 2s... ({retries} left)")
            await asyncio.sleep(2)


async def get_session():
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session


app = FastAPI(title="Netra API", version="0.1.0", debug=True)

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


async def get_current_user(
    token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)
):
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
async def register(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
):
    # Check existing
    result = await session.execute(
        select(User).where(User.username == form_data.username)
    )
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
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
):
    # Fetch User
    result = await session.execute(
        select(User).where(User.username == form_data.username)
    )
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
    return {
        "username": current_user.username,
        "id": current_user.id,
        "preferences": current_user.preferences or {},
    }


@app.put("/users/me/preferences")
async def update_user_preferences(
    prefs: dict,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    current_user.preferences = {**(current_user.preferences or {}), **prefs}
    session.add(current_user)
    await session.commit()
    return current_user.preferences


# Catch-all for SPA (must be last)


@app.post("/api/scan")
async def trigger_v2_scan(request: ScanRequest):
    """
    v2 Endpoint: Pushes target to Redis Stream for Distributed Scanning.
    """
    try:
        # Connect to the Ingestion Stream
        stream = NetraStream(stream_key="netra:events:ingest")
        await stream.publish_target(
            request.target, source="api", options=request.options
        )
        return {
            "status": "queued",
            "target": request.target,
            "message": "Dispatched to Ingestion Worker",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/debug/ml-status")
async def debug_ml_status():
    global ML_MODEL
    buckets = []
    if minio_client:
        try:
            buckets = [b.name for b in minio_client.list_buckets()]
        except Exception as e:
            buckets = [f"Error: {e}"]

    return {
        "ml_model_loaded": ML_MODEL is not None,
        "ml_model_type": str(type(ML_MODEL)) if ML_MODEL else "None",
        "heuristic_mode": getattr(ZombieHunter, "_heuristic_mode", True), # Default to True (Heuristic) if not set
        "minio_connected": minio_client is not None,
        "minio_buckets": buckets,
        "env_minio_url": MINIO_URL,
    }


@app.on_event("startup")
async def on_startup():
    await init_db()
    global db
    db = NeoGraph()
    print(f"DEBUG: BASE_DIR={BASE_DIR}")
    print(f"DEBUG: STATIC_DIR={STATIC_DIR}")
    print(f"DEBUG: STATIC_DIR={STATIC_DIR}")
    if os.path.exists(STATIC_DIR):
        print(f"DEBUG: STATIC_DIR exists. Contents: {os.listdir(STATIC_DIR)}")
    else:
        print(f"DEBUG: STATIC_DIR DOES NOT EXIST at {STATIC_DIR}")

    # Phase 3.2: Load ML Model (if exists in MinIO)
    global ML_MODEL
    if minio_client:
        try:
            if minio_client.bucket_exists("ml-models"):
                # Download model to memory
                response = minio_client.get_object("ml-models", "risk_model_v1.pkl")
                model_bytes = io.BytesIO(response.read())
                response.close()
                response.release_conn()
                ML_MODEL = pickle.load(model_bytes)
                print("ML Engine: Loaded risk_model_v1.pkl successfully.")
            else:
                print("ML Engine: No model bucket found. Running in Heuristic Mode.")
        except Exception as mle:
            print(f"ML Engine Init Failed: {mle}")

    # Phase 4: Load Zombie API (NLP) Model
    from netra.ml.zombie_hunter import ZombieHunter

    print("ML Engine: Loading Zombie Hunter...")
    ZombieHunter.load_model(minio_client)


@app.post("/internal/ml/predict-zombie")
async def predict_zombie(request: Request):
    """
    Internal Endpoint: Used by Ruby Scanners to access Python ML Models.
    """
    from netra.ml.zombie_hunter import ZombieHunter

    data = await request.json()
    candidates = data.get("candidates", [])

    results = []
    for c in candidates:
        is_hit = ZombieHunter.predict_is_api(c)
        if is_hit:
            comment = ZombieHunter.consult_oracle(c, True)
            results.append(
                {"path": c, "commentary": comment, "confidence": 0.95}
            )  # Mock confidence for now

    return {"positives": results}

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
            "static_contents": os.listdir(STATIC_DIR)
            if os.path.exists(STATIC_DIR)
            else [],
            "app_netra_contents": os.listdir("/app/netra")
            if os.path.exists("/app/netra")
            else "Not found",
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
        query_target = (
            "MERGE (d:Domain {name: $name}) SET d.last_seen = timestamp() RETURN d"
        )
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
                db.cypher_query(
                    query_vuln,
                    {
                        "domain": target,
                        "name": v.get("type", "Unknown"),
                        "severity": v.get("severity", "Medium"),
                    },
                )

        # Merge other vulnerabilities (IAMScanner, RubyScanner generic)
        for scanner_key in scan_results:
            if scanner_key in [
                "IAMScanner",
                "ResilienceScanner",
                "RubyScanner_banner_grabber",
            ]:
                s_vulns = scan_results[scanner_key].get("vulnerabilities", [])
                for v in s_vulns:
                    query_v = """
                    MATCH (d:Domain {name: $domain})
                    MERGE (v:Vulnerability {name: $name, severity: $severity})
                    MERGE (d)-[:HAS_VULNERABILITY]->(v)
                    """
                    db.cypher_query(
                        query_v,
                        {
                            "domain": target,
                            "name": v.get("type", "Unknown"),
                            "severity": v.get("severity", "Info"),
                        },
                    )



        # 5. ML Insight: Calculate Risk Score
        # 5. ML Insight: Calculate Risk Score
        # Strategy: Use Trained Model if available, else Heuristic (Cold Start)
        risk_score = 0
        risk_source = "Heuristic"

        if ML_MODEL:
            # Phase 3.2: Online Inference (using Snorkel-trained artifact)
            try:
                # 1. Feature Extraction
                n_crit = 0
                n_high = 0
                n_med = 0
                n_low = 0

                if "ThreatScanner" in scan_results:
                    for v in scan_results["ThreatScanner"].get("vulnerabilities", []):
                        sev = v.get("severity", "Info")
                        if sev == "Critical":
                            n_crit += 1
                        elif sev == "High":
                            n_high += 1
                        elif sev == "Medium":
                            n_med += 1
                        elif sev == "Low":
                            n_low += 1

                n_ports = len(scan_results.get("PortScanner", {}).get("open_ports", []))

                # 2. Vectorize: [crit, high, med, low, ports] (Must match train.py order)
                features = [[n_crit, n_high, n_med, n_low, n_ports]]

                # 3. Predict
                if hasattr(ML_MODEL, "predict"):
                    prediction = ML_MODEL.predict(features)[0]
                    risk_score = float(prediction)
                    risk_source = "ML_Model_v1"
                    print(f"ML Inference Success: Predicted Risk {risk_score}")

            except Exception as ml_e:
                print(f"ML Inference Failed: {ml_e}. Falling back to Heuristic.")
                print(f"ML Inference Failed: {ml_e}. Falling back to Heuristic.")

        if risk_score == 0:  # Fallback or Heuristic Mode
            # Score = (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 0.5) + (OpenPorts * 1)

            # Count Vulns
            if "ThreatScanner" in scan_results:
                vulns = scan_results["ThreatScanner"].get("vulnerabilities", [])
                for v in vulns:
                    sev = v.get("severity", "Info")
                    if sev == "Critical":
                        risk_score += 10
                    elif sev == "High":
                        risk_score += 5
                    elif sev == "Medium":
                        risk_score += 2
                    elif sev == "Low":
                        risk_score += 0.5

            # Count Ports
            if "PortScanner" in scan_results:
                ports = scan_results["PortScanner"].get("open_ports", [])
                risk_score += len(ports)

            # Normalize to 0-100 (Cap)
            risk_score = min(risk_score, 100)
            risk_source = "Heuristic (Rule-Based)"

        # Update Domain Node with ML Score
        query_score = "MATCH (d:Domain {name: $name}) SET d.risk_score = $score, d.risk_source = $source RETURN d"
        db.cypher_query(
            query_score, {"name": target, "score": risk_score, "source": risk_source}
        )
        return risk_score

    except Exception as e:
        print(f"Graph Sync Error: {e}")
        return 0


async def upload_to_datalake(scan_id: int, results: dict):
    """
    ML Phase 3.1: Archives raw scan logs to MinIO (S3) for offline training.
    """
    if not minio_client:
        return
    try:
        bucket = "netra-lake"
        if not minio_client.bucket_exists(bucket):
            minio_client.make_bucket(bucket)

        data = json.dumps(results).encode("utf-8")
        minio_client.put_object(
            bucket,
            f"scans/{scan_id}.json",
            io.BytesIO(data),
            len(data),
            content_type="application/json",
        )
        print(f"Data Lake: Archived scan {scan_id} to {bucket}")
    except Exception as e:
        print(f"Data Lake Error: {e}")


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
            if opts.get("recon", True):  # Default to true
                v_engine.register_scanner(CTScanner())

            # Default Scanners (Ruby Bridge)
            # Port Scanning + Banner Grabbing
            v_engine.register_scanner(
                RubyScanner("banner_grabber.rb", name="PortScanner")
            )

            # Threat Intel (SPF/DMARC/Robots)
            v_engine.register_scanner(
                RubyScanner("threat_scan.rb", name="ThreatScanner")
            )

            # IAM & Session Analysis
            v_engine.register_scanner(RubyScanner("iam_scan.rb", name="IAMScanner"))

            # Resilience / Rate Limit
            if opts.get(
                "resilience", False
            ):  # Only if resilience is toggled (assuming we use this option)
                v_engine.register_scanner(
                    RubyScanner("resilience_scan.rb", name="ResilienceScanner")
                )
                v_engine.register_scanner(
                    RubyBridge(script_name="dos_check.rb", name="DoSScanner")
                )
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
            v_engine.register_scanner(
                RubyScanner("resilience_scan.rb", name="ResilienceScanner")
            )

            # Aggressive DoS Checks (if requested)
            if opts.get("resilience", False) or opts.get("dos", False):
                v_engine.register_scanner(
                    RubyBridge(script_name="dos_check.rb", name="DoSScanner")
                )

            if opts.get("secrets", False):
                v_engine.register_scanner(SecretScanner())

            if opts.get("api_fuzz", False) or opts.get("zombie", False):
                # v_engine.register_scanner(ZombieScanner()) # Deprecated in favor of Ruby Hybrid
                v_engine.register_scanner(
                    RubyScanner("zombie_scan.rb", name="ZombieScanner")
                )
                v_engine.register_scanner(RubyScanner("rce_scan.rb", name="RCEScanner"))

            if opts.get("cloud", False):
                v_engine.register_scanner(CloudScanner())
            
            # Sprint 2: TurboScan (Go)
            # Default to enabled if not explicitly disabled
            if opts.get("TurboScan", False): 
                from netra.core.modules.go_bridge import GoScanner
                v_engine.register_scanner(GoScanner())

            # Sprint 3: LogCruncher (Rust)
            if opts.get("LogCruncher", False):
                from netra.core.modules.rust_bridge import RustScanner
                v_engine.register_scanner(RustScanner())

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
            results = await asyncio.wait_for(
                v_engine.scan_target(scan.target), timeout=600
            )

            scan.results = results
            scan.results = results
            scan.status = "completed"

            # Phase 3.1: Data Lake Archival
            await upload_to_datalake(scan.id, results)

            # Sync to Graph (New Feature) & Get Score
            risk_score = await sync_graph_results(results, scan.target)
            scan.risk_score = int(risk_score)

            # Post-Scan Actions: DefectDojo Import
            if (
                opts.get("defect_dojo_url")
                and opts.get("defect_dojo_key")
                and opts.get("engagement_id")
            ):
                try:
                    logger.info("Triggering DefectDojo Import...")
                    dd_client = DefectDojoClient(
                        opts.get("defect_dojo_url"), opts.get("defect_dojo_key")
                    )
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
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    scan = Scan(
        target=scan_in.target,
        scan_type=scan_in.scan_type,
        options=scan_in.options,
        status="pending",
        user_id=current_user.id,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # Distributed (Drone) Mode vs Local
    if REDIS_URL:
        try:
            redis = aioredis.from_url(
                REDIS_URL, encoding="utf-8", decode_responses=True
            )
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
async def list_scans(
    offset: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # Filter by user
    query = (
        select(Scan).where(Scan.user_id == current_user.id).offset(offset).limit(limit)
    )
    result = await session.execute(query)
    scans = result.scalars().all()
    return scans


@app.get("/scans/{scan_id}", response_model=ScanRead)
async def read_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this scan"
        )
    return scan


@app.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this scan"
        )

    session.delete(scan)
    await session.commit()
    return {"ok": True}

    if not scan.results:
        return {"error": "Scan has no results yet"}

    reporter = SARIFReporter()
    sarif_data = reporter.convert_scan_results(scan.results, scan.target)

    return sarif_data


# Graph & Asset Endpoints (Real Data Wiring)
# Graph & Asset Endpoints (Real Data Wiring)
from neomodel import config 
# Note: We use global 'db' (NeoGraph) for queries, avoiding neomodel.db shadowing


# Initialize Neo4j (Lazy connection)
# Ensure NEO4J_URL is suitable for neomodel (bolt://user:pass@host:port)
config.DATABASE_URL = os.getenv("NEO4J_URL", "bolt://neo4j:password_change_me@neo4j:7687")


@app.get("/api/graph")
async def get_graph_data():
    """
    Returns the Knowledge Graph (Nodes & Edges) for visualization.
    """
    try:
        # Fetch generic graph data (Limit to avoid exploding the UI)
        # Use OPTIONAL MATCH to get at least nodes if no relationships exist
        query = "MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 200"
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
                    label = (
                        node.get("name")
                        or node.get("address")
                        or node.get("port")
                        or node.get("resource_id")
                        or node.get("fingerprint")
                        or "Unknown"
                    )
                    nodes[node_id] = {
                        "id": node_id,
                        "group": labels[0] if labels else "Node",
                        "label": label,
                        "properties": dict(node),
                    }
                return node_id

            s_id = process_node(source_node)
            t_id = process_node(target_node)

            links.append({"source": s_id, "target": t_id, "type": rel.type})

        return {"nodes": list(nodes.values()), "links": links}

    except Exception as e:
        print(f"Graph Error: {e}")
        return {"nodes": [], "links": []}


class TagRequest(BaseModel):
    node_id: str
    tag: str


@app.post("/api/graph/tag")
async def tag_graph_node(
    req: TagRequest, current_user: User = Depends(get_current_user)
):
    """
    Manually tags a node in the graph (e.g. Critical, Verified).
    """
    try:
        # We need to find the node by ID or Label/Address.
        # Ideally, our UI passes the specific Neo4j ID or a unique key.
        # For this implementation, we assume node_id corresponds to the 'name' or 'address'.

        # Cypher: Match node where id or name matches
        query = """
        MATCH (n)
        WHERE elementId(n) = $id OR n.name = $id OR n.address = $id
        SET n.tag = $tag
        RETURN n
        """
        # Note: elementId() is for Neo4j 5+. ID() is deprecated but widely used.
        # Let's try matching property first as our UI uses IPs/Domains as keys often.
        db.cypher_query(query, {"id": req.node_id, "tag": req.tag})
        return {"status": "tagged", "node": req.node_id, "tag": req.tag}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

        return {"nodes": list(nodes.values()), "links": links}
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
            assets.append(
                {
                    "id": d.id,
                    "name": d["name"],
                    "type": "Domain",
                    "details": f"Registrar: {d.get('registrar', 'N/A')}",
                    "status": "active",  # Placeholder
                }
            )

        for row in ips:
            i = row[0]
            assets.append(
                {
                    "id": i.id,
                    "name": i["address"],
                    "type": "IP Address",
                    "details": f"Version: {i.get('version', 'IPv4')}",
                    "status": "active",
                }
            )

        return assets
    except Exception as e:
        print(f"Asset Query Error: {e}")


@app.get("/api/vulnerabilities")
async def get_all_vulnerabilities(
    limit: int = 100, session: AsyncSession = Depends(get_session)
):
    """
    Aggregates vulnerabilities from all recent scans.
    """
    # In a real system, we might query Neo4j for (v:Vulnerability), but since we store report JSON in PG:
    result = await session.execute(
        select(Scan).order_by(Scan.timestamp.desc()).limit(50)
    )
    scans = result.scalars().all()

    vulns = []
    for scan in scans:
        if not scan.results:
            continue

        # Helper to extract from scanner dicts
        for scanner_name, data in scan.results.items():
            # Check for standard 'vulnerabilities' list
            if isinstance(data, dict) and "vulnerabilities" in data:
                for v in data["vulnerabilities"]:
                    # Normalize
                    vulns.append(
                        {
                            "id": str(uuid.uuid4())[:8],
                            "scan_id": scan.id,
                            "target": scan.target,
                            "type": v.get("type", "Unknown"),
                            "severity": v.get("severity", "Info"),
                            "scanner": scanner_name,
                            "details": v.get("details", "") or v.get("description", ""),
                            "timestamp": scan.timestamp.isoformat()
                            if scan.timestamp
                            else "",
                        }
                    )

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


@app.get("/api/graph/predict")
async def predict_shadow_it():
    """
    Predicts 'Shadow IT' links using Behavioral Similarity Analysis (Lightweight AI).
    Finds assets that share similar open ports/services but aren't explicitly linked.
    """
    try:
        # Use simple cypher query via global db
        if not db:
             return {"predicted_edges": [], "status": "Graph database not connected"}

        query = """
        MATCH (h1:Host)-[:OPEN_ON]->(p:Port)<-[:OPEN_ON]-(h2:Host)
        WHERE id(h1) < id(h2)
        WITH h1, h2, count(p) as shared_ports, collect(p.port) as common_ports
        MATCH (h1)-[:OPEN_ON]->(p1:Port)
        WITH h1, h2, shared_ports, common_ports, count(p1) as total_ports_h1
        MATCH (h2)-[:OPEN_ON]->(p2:Port)
        WITH h1, h2, shared_ports, common_ports, total_ports_h1, count(p2) as total_ports_h2
        
        // Calculate Jaccard Similarity for Ports: (Intersection / Union)
        WITH h1, h2, shared_ports, common_ports, 
             toFloat(shared_ports) / (total_ports_h1 + total_ports_h2 - shared_ports) as similarity
        
        WHERE similarity > 0.3  // Threshold: at least 30% overlap
        
        RETURN h1.ip as source, h2.ip as target, similarity, common_ports
        ORDER BY similarity DESC
        LIMIT 10
        """
        
        # Execute using global NeoGraph wrapper
        records, _, _ = db.driver.execute_query(query)

        
        predictions = []
        for record in records:
            similarity_pct = round(record["similarity"] * 100, 1)
            common = record["common_ports"]
            
            # Generate "Intelligent" Reason
            reason = f"High structural similarity ({similarity_pct}%). Both hosts run {len(common)} identical services (Ports: {common[:3]}{'...' if len(common)>3 else ''})."
            
            predictions.append({
                "source": record["source"], 
                "target": record["target"], 
                "confidence": similarity_pct,
                "reason": reason,
                "type": "Shadow Correlation"
            })
            
        return {"predictions": predictions, "count": len(predictions)}

    except Exception as e:
        print(f"Prediction Error: {e}")
        return {"predictions": [], "error": str(e)}

@app.get("/api/stats")
async def get_stats(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
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
                threats = s.results.get("ThreatScanner", {}).get("vulnerabilities", [])
                vuln_count += len(threats)

        # Recent Risk History (Refined)
        history_query = (
            select(Scan)
            .where(Scan.user_id == current_user.id)
            .order_by(Scan.timestamp.desc())
            .limit(5)
        )
        history_res = await session.execute(history_query)
        history_scans = history_res.scalars().all()
        risk_trend = [s.risk_score for s in reversed(history_scans)]
        if not risk_trend:
            risk_trend = [0] * 5

        return {
            "scans": scan_count,
            "assets": asset_count,
            "vulns": vuln_count,
            "risk_trend": risk_trend,
        }
    except Exception as e:
        print(f"Stats Error: {e}")
        return {"scans": 0, "assets": 0, "vulns": 0, "risk_trend": []}


# Catch-all for SPA (must be last)
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    # Allow API routes to pass through (though they should be matched before this if defined above)
    if (
        full_path.startswith("api")
        or full_path.startswith("scans")
        or full_path.startswith("docs")
        or full_path.startswith("openapi.json")
    ):
        raise HTTPException(status_code=404, detail="Not Found")

    # 1. Try to serve exact file from static directory (e.g. neural.html, favicon.ico)
    requested_path = os.path.join(STATIC_DIR, full_path)
    if os.path.exists(requested_path) and os.path.isfile(requested_path):
        return FileResponse(requested_path)

    # 2. Serve index.html for everything else (SPA fallback)
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "Static UI not found. Ensure netra/static/index.html exists."}
