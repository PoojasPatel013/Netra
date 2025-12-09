import asyncio
import typer
import json
from typing import Optional
from vortex.core.engine import VortexEngine
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner
from vortex.core.modules.pentest import PentestEngine

app = typer.Typer()

@app.command()
def version():
    """
    Show version.
    """
    print("Vortex v0.1.0")

@app.command()
def scan(target: str = typer.Argument(..., help="Target URL"), auto_exploit: bool = typer.Option(False, "--auto-exploit", help="Enable auto exploitation"), ports: str = typer.Option(None, "--ports", "-p", help="Comma separated list of ports")):
    """
    Run a scan against a target.
    """
    async def run():
        engine = VortexEngine()
        
        # Configure Port Scanner
        port_list = None
        if ports:
            port_list = [int(p) for p in ports.split(",")]
        engine.register_scanner(PortScanner(ports=port_list))
        
        engine.register_scanner(HTTPScanner())
        
        if auto_exploit:
            engine.register_scanner(PentestEngine())
            
        results = await engine.scan_target(target)
        print(json.dumps(results, indent=2))

    asyncio.run(run())

if __name__ == "__main__":
    app()
