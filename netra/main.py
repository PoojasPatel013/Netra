import asyncio
import typer
import json
import uvicorn
from netra.core.engine import NetraEngine
from netra.core.modules.network import PortScanner
from netra.core.modules.http import HTTPScanner
from netra.core.modules.threat import ThreatScanner
from netra.core.modules.cloud import CloudScanner
from netra.core.modules.acquisition import AcquisitionScanner
from netra.core.modules.compliance import ComplianceEngine
from netra.core.modules.go_bridge import GoScanner
from netra.core.modules.rust_bridge import RustScanner
from netra.core.reporter import SARIFReporter

app = typer.Typer()

# Global Scanners
scanners = [
    PortScanner(),
    HTTPScanner(),
    ThreatScanner(),
    CloudScanner(),
    AcquisitionScanner(),
    GoScanner(), # TurboScan (Go)
    RustScanner(), # LogCruncher (Rust)
]


@app.command()
def version():
    """
    Show version.
    """
    print("Netra v0.1.0")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
):
    """
    Start the API server.
    """
    print(f"Starting Netra API on {host}:{port}")
    uvicorn.run("netra.api.main:app", host=host, port=port, reload=True)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    auto_exploit: bool = typer.Option(
        False, "--auto-exploit", help="Enable auto exploitation"
    ),
    ports: str = typer.Option(
        None, "--ports", "-p", help="Comma separated list of ports"
    ),
    cloud: bool = typer.Option(
        False, "--cloud", help="Enable Cloud Infrastructure Scanner"
    ),
    iot: bool = typer.Option(False, "--iot", help="Enable IoT Protocol Fuzzer"),
    graphql: bool = typer.Option(
        False, "--graphql", help="Enable GraphQL Introspection Scanner"
    ),
    export_sarif: str = typer.Option(
        None, "--export-sarif", help="Export results to SARIF file (e.g. results.sarif)"
    ),
):
    """
    Run a scan against a target.
    """

    async def run():
        engine = NetraEngine()

        # Configure Port Scanner
        port_list = None
        if ports:
            port_list = [int(p) for p in ports.split(",")]
        engine.register_scanner(PortScanner(ports=port_list))

        engine.register_scanner(HTTPScanner())

        if cloud:
            engine.register_scanner(CloudScanner())

        if iot:
            engine.register_scanner(IoTScanner())

        if graphql:
            engine.register_scanner(GraphQLScanner())

        if auto_exploit:
            engine.register_scanner(PentestEngine())

        results = await engine.scan_target(target)
        print(json.dumps(results, indent=2))

        if export_sarif:
            reporter = SARIFReporter()
            sarif_report = reporter.convert_scan_results(results, target)
            with open(export_sarif, "w") as f:
                json.dump(sarif_report, f, indent=2)
            print(f"\n[+] SARIF report exported to {export_sarif}")

    asyncio.run(run())


if __name__ == "__main__":
    app()
