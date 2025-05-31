# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Code quality and type checking
mypy a2logviz/          # Type checking (strict configuration)
ruff check a2logviz/    # Linting  
black a2logviz/         # Code formatting
pytest                  # Run tests (uses pytest-asyncio)

# Testing log parsing without server
a2logviz-test /path/to/logfile
python -m a2logviz.main test-parser access.log --debug

# Run application
a2logviz /var/log/apache2/access.log                    # Explorer mode (default)
a2logviz --mode dashboard --port 8080 access.log       # Dashboard mode
```

**External Dependency**: ClickHouse Local must be installed separately: `curl https://clickhouse.com/ | sh`

## Architecture Overview

### Dual-Mode Web Application

The application operates in two distinct modes with different server implementations:

- **Explorer Mode** (`ExplorationServer`): Advanced column-based analysis, anomaly detection, interactive drill-downs
- **Dashboard Mode** (`LogVisualizationServer`): Traditional charts and visualizations

### Data Processing Pipeline

```
Log Files → ApacheLogParser → Pandas DataFrame → ClickHouse Local CSV → Web Interface
```

**Key Pattern**: All data is loaded into memory as a Pandas DataFrame, then exported to a temporary CSV file for ClickHouse Local SQL analysis. No streaming - entire dataset must fit in memory.

### Log Parsing Architecture

`ApacheLogParser` supports three distinct format types:
1. **Predefined names**: `common`, `combined`, `vhost_combined`, `combined_with_time`
2. **Apache LogFormat strings**: Uses `apachelogs` library for parsing
3. **Custom regex patterns**: With named groups for field extraction

The parser automatically detects format type and uses hybrid approach (apachelogs + regex fallback).

## Core Component Interactions

### ClickHouse Integration Pattern

`ClickHouseLocalClient` uses subprocess execution with temporary CSV files:
- Generates type-mapped schema from DataFrame dtypes
- All queries executed via subprocess with JSON output parsing
- Built-in security and analysis queries for common patterns

### Analysis Engine Architecture

**Column Analysis** (`ColumnAnalyzer`):
- Automatic data type inference (IP addresses, URLs, user agents, numeric, categorical)
- Cardinality analysis and anomaly scoring based on distribution patterns
- Type-aware SQL query generation (handles Int64/Float64 vs String null checks)

**Security Detection** (`AbuseDetector` + `AdvancedAnomalyDetector`):
- Abuse detection runs once at startup, results cached and served via API
- Four detection patterns: brute force, DDoS, scanning, bot behavior
- Anomaly detection runs on-demand with temporal filtering
- Both use statistical thresholds and confidence scoring

### Web Server Architecture

Both servers auto-generate HTML templates on startup using Jinja2:
- **ExplorationServer**: Bootstrap + Plotly.js with tabbed interface (Data Explorer, Security Alerts, Advanced Anomalies)
- **WebServer**: Traditional dashboard with Plotly visualizations

Templates are created programmatically in `_create_templates()` methods, not stored as separate files.

## Important Technical Patterns

### Type Safety and Error Handling

- Full type annotations with strict mypy configuration
- Dataclass-based models for structured data (`LogEntry`, `AbusePattern`, `AnomalyAlert`, `ColumnMetadata`)
- Graceful degradation: failed column analysis creates minimal metadata instead of crashing
- Type-aware SQL query generation prevents ClickHouse type conversion errors

### Security-Focused Analysis

- Security alerts integrated into web interface with severity-based prioritization  
- Abuse patterns displayed with affected IPs, request counts, and confidence scores
- Temporal analysis for detecting attack patterns over time
- Anomaly detection with actionable recommendations

### Configuration and Extensibility

- Plugin-like detection methods in `AbuseDetector` - easily extensible
- Column analysis types easily extendable via `_determine_column_type()`
- Time-based filtering throughout analysis pipeline
- Mode switching between exploration and dashboard interfaces

### Performance Considerations

- ClickHouse Local provides fast SQL analysis on moderate datasets
- Frontend uses Plotly for interactive visualizations with Bootstrap responsive UI
- HTML templates generated once at startup, not on each request
- All analysis results cached at application startup

## Development Notes

- **Memory Usage**: Entire dataset loaded into memory - not suitable for extremely large log files
- **Temporary Files**: Automatic cleanup of CSV files in `/tmp/a2logviz_*` directories
- **SQL Query Safety**: All column names escaped with backticks, type-aware null condition handling
- **Frontend**: Uses CDN-hosted Bootstrap and Plotly.js libraries, no build process required