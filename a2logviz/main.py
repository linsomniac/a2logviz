"""Main entry point for the Apache log visualization tool."""

import sys
from pathlib import Path

import click
import uvicorn

from .abuse_detector import AbuseDetector
from .anomaly_detector import AdvancedAnomalyDetector
from .clickhouse_client import ClickHouseLocalClient
from .exploration_server import ExplorationServer
from .log_parser import ApacheLogParser
from .web_server import LogVisualizationServer


@click.command()
@click.option(
    "--log-format",
    default="combined",
    help="Apache log format: predefined name (common, combined, combined_with_time, vhost_combined), Apache LogFormat string (e.g., '%h %l %u %t \"%r\" %>s %O'), or custom regex",
)
@click.option("--host", default="127.0.0.1", help="Host to bind the web server to")
@click.option("--port", default=8000, type=int, help="Port to bind the web server to")
@click.option(
    "--mode",
    default="explorer",
    type=click.Choice(["explorer", "dashboard"]),
    help="Interface mode: explorer (advanced analysis) or dashboard (simple charts)",
)
@click.option(
    "--min-suspicious-requests",
    default=100,
    type=int,
    help="Minimum requests to flag as suspicious",
)
@click.argument("log_files", nargs=-1, required=True)
def main(
    log_format: str,
    host: str,
    port: int,
    mode: str,
    min_suspicious_requests: int,
    log_files: tuple[str, ...],
) -> None:
    """Apache log visualization tool with abuse detection.

    Parse Apache log files and serve a web dashboard for analyzing web traffic
    and detecting potential abuse patterns.

    LOG_FILES: One or more Apache log files to analyze
    """
    # Validate log files exist
    log_paths = []
    for log_file in log_files:
        path = Path(log_file)
        if not path.exists():
            click.echo(f"Error: Log file {log_file} does not exist", err=True)
            sys.exit(1)
        log_paths.append(path)

    click.echo("Starting Apache Log Visualizer...")
    click.echo(f"Log format: {log_format}")
    click.echo(f"Log files: {', '.join(str(p) for p in log_paths)}")

    try:
        # Parse log files
        click.echo("Parsing log files...")
        parser = ApacheLogParser(log_format)
        df = parser.parse_files_to_dataframe(log_paths)

        if df.empty:
            click.echo(
                "Error: No valid log entries found in the provided files", err=True
            )
            sys.exit(1)

        click.echo(f"Successfully parsed {len(df)} log entries")

        # Set up ClickHouse Local
        click.echo("Setting up ClickHouse Local database...")
        clickhouse_client = ClickHouseLocalClient()
        clickhouse_client.setup_database(df)

        # Run abuse detection
        click.echo("Running abuse detection analysis...")
        abuse_detector = AbuseDetector(df)
        abuse_patterns = abuse_detector.analyze_all_patterns()

        # Print summary of detected patterns
        total_patterns = sum(len(patterns) for patterns in abuse_patterns.values())
        click.echo(f"Detected {total_patterns} potential abuse patterns:")
        for pattern_type, patterns in abuse_patterns.items():
            if patterns:
                click.echo(f"  - {pattern_type}: {len(patterns)} patterns")

        # Start web server based on mode
        click.echo(f"Starting web server in {mode} mode on http://{host}:{port}")

        if mode == "explorer":
            # Use advanced exploration server
            server = ExplorationServer(clickhouse_client)
            # Pass abuse patterns to the exploration server
            server.set_abuse_patterns(abuse_patterns)
            app = server.get_app()

            # Add enhanced anomaly detection
            anomaly_detector = AdvancedAnomalyDetector(clickhouse_client)

            @app.get("/api/anomalies")
            async def get_anomalies(
                start_time: str = None, end_time: str = None
            ) -> dict:
                """Get advanced anomaly detection results."""
                time_filter = None
                if start_time and end_time:
                    time_filter = {"start": start_time, "end": end_time}
                return {
                    "alerts": [
                        {
                            "alert_type": alert.alert_type,
                            "severity": alert.severity,
                            "column": alert.column,
                            "description": alert.description,
                            "value": alert.value,
                            "frequency": alert.frequency,
                            "percentage": alert.percentage,
                            "recommendations": alert.recommendations or [],
                        }
                        for alert in anomaly_detector.detect_all_anomalies(time_filter)
                    ]
                }

            @app.get("/api/security-summary")
            async def get_security_summary(
                start_time: str = None, end_time: str = None
            ) -> dict:
                """Get security summary."""
                time_filter = None
                if start_time and end_time:
                    time_filter = {"start": start_time, "end": end_time}
                return anomaly_detector.get_security_summary(time_filter)

            click.echo("Advanced Explorer available at:")
            click.echo(f"  - Main explorer: http://{host}:{port}/")
            click.echo(f"  - Column analysis: http://{host}:{port}/api/columns")
            click.echo(f"  - Anomaly detection: http://{host}:{port}/api/anomalies")
            click.echo(
                f"  - Security summary: http://{host}:{port}/api/security-summary"
            )

        else:
            # Use traditional dashboard
            server = LogVisualizationServer(clickhouse_client)
            app = server.get_app()

            # Add abuse detection endpoint
            @app.get("/api/abuse-patterns")
            async def get_abuse_patterns() -> dict:
                """Get detected abuse patterns."""
                return {
                    "patterns": abuse_patterns,
                    "summary": {
                        pattern_type: len(patterns)
                        for pattern_type, patterns in abuse_patterns.items()
                    },
                }

            @app.get("/api/top-threats")
            async def get_top_threats() -> list:
                """Get top security threats."""
                threats = abuse_detector.get_top_threats(limit=10)
                return [
                    {
                        "pattern_type": threat.pattern_type,
                        "severity": threat.severity,
                        "description": threat.description,
                        "affected_ips": threat.affected_ips,
                        "request_count": threat.request_count,
                        "confidence": threat.confidence,
                        "details": threat.details,
                    }
                    for threat in threats
                ]

            click.echo("Dashboard available at the following endpoints:")
            click.echo(f"  - Main dashboard: http://{host}:{port}/")
            click.echo(f"  - Top IPs API: http://{host}:{port}/api/top-ips")
            click.echo(f"  - Abuse patterns: http://{host}:{port}/api/abuse-patterns")
            click.echo(f"  - Top threats: http://{host}:{port}/api/top-threats")

        click.echo("Press Ctrl+C to stop the server")

        uvicorn.run(app, host=host, port=port, log_level="info")

    except KeyboardInterrupt:
        click.echo("\nShutting down...")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    finally:
        # Cleanup
        try:
            clickhouse_client.cleanup()
        except:
            pass


@click.command()
@click.option(
    "--log-format",
    default="combined",
    help="Apache log format: predefined name, Apache LogFormat string, or custom regex",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug output for parsing",
)
@click.argument("log_file")
def test_parser(log_format: str, debug: bool, log_file: str) -> None:
    """Test log parsing on a single file without starting the server."""
    path = Path(log_file)
    if not path.exists():
        click.echo(f"Error: Log file {log_file} does not exist", err=True)
        sys.exit(1)

    parser = ApacheLogParser(log_format)

    click.echo(f"Testing parser with format: {log_format}")
    click.echo(f"Parser uses apachelogs: {parser.use_apachelogs}")
    click.echo(f"Parsing first 10 lines of: {log_file}")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= 10:
                break

            if debug:
                click.echo(f"\nDEBUG: Processing line {i+1}")
                click.echo(f"DEBUG: Raw line: {line.strip()}")

                if parser.use_apachelogs and parser.apache_parser:
                    try:
                        entry_raw = parser.apache_parser.parse(line.strip())
                        click.echo(f"DEBUG: apachelogs parsed successfully")
                        click.echo(
                            f"DEBUG: Available attributes: {[attr for attr in dir(entry_raw) if not attr.startswith('_')]}"
                        )
                        click.echo(
                            f"DEBUG: remote_host: {getattr(entry_raw, 'remote_host', 'N/A')}"
                        )
                        click.echo(
                            f"DEBUG: request_time: {getattr(entry_raw, 'request_time', 'N/A')}"
                        )
                        click.echo(
                            f"DEBUG: final_status: {getattr(entry_raw, 'final_status', 'N/A')}"
                        )
                        if hasattr(entry_raw, "headers_in"):
                            click.echo(f"DEBUG: headers_in: {entry_raw.headers_in}")
                    except Exception as e:
                        click.echo(f"DEBUG: apachelogs parsing failed: {e}")

            entry = parser.parse_line(line)
            if entry:
                click.echo(f"✓ Line {i+1}: {entry.remote_host} - {entry.request_line}")
                if debug:
                    click.echo(f"DEBUG: Parsed entry: {entry}")
            else:
                click.echo(f"✗ Line {i+1}: Failed to parse")
                click.echo(f"    Raw line: {line.strip()}")


if __name__ == "__main__":
    main()
