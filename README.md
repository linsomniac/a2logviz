# Apache Log Visualizer (a2logviz)

A Python tool that parses Apache log files, processes them with ClickHouse Local, and serves a web dashboard for visualizing web requests and detecting potential abuse patterns.

![A2LogViz Screenshot](screenshot/a2logviz.png)

## Features

- **Configurable Log Parsing**: Supports predefined formats, Apache LogFormat strings, and custom regex patterns
- **ClickHouse Integration**: Uses ClickHouse Local for fast log data processing and analysis
- **Advanced Data Explorer**: Interactive column analysis and exploration interface
- **Intelligent Anomaly Detection**: Advanced algorithms to detect:
  - Traffic spikes and unusual patterns
  - IP-based attacks (DDoS, brute force)
  - Suspicious user agents and bots
  - Path-based scanning and attacks
  - Response size anomalies
  - Temporal anomalies
- **Interactive Drill-Down**: Select columns for detailed group analysis with time filtering
- **Security Monitoring**: Real-time security alerts with actionable recommendations
- **Two Interface Modes**: 
  - **Explorer Mode**: Advanced data exploration and anomaly detection
  - **Dashboard Mode**: Traditional charts and visualizations
- **Type Safety**: Full type annotations with mypy checking
- **Code Quality**: Formatted with black and linted with ruff

## Installation

1. Install dependencies:

```bash
pip install -e ".[dev]"
```

2. Install ClickHouse Local:

   curl https://clickhouse.com/ | sh

## Usage

### Basic Usage

```bash
# Start advanced explorer mode (default)
a2logviz /var/log/apache2/access.log

# Start traditional dashboard mode
a2logviz --mode dashboard /var/log/apache2/access.log

# Specify predefined log format and custom port
a2logviz --log-format combined --port 8080 access.log error.log

# Parse with Apache LogFormat string
a2logviz --log-format '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"' access.log

# Parse with custom regex format
a2logviz --log-format "(?P<remote_host>\S+) - - \[(?P<timestamp>[^\]]+)\] \"(?P<request_line>[^\"]*)\" (?P<status_code>\d+) (?P<response_size>\S+)" custom.log

# Use complex Apache LogFormat with virtual hosts and custom headers
a2logviz --log-format '%V %h %a "%{X-Real-IP}i" "%{X-Forwarded-For}i" %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D "%{signOnUserName}C" %{RGSessionId}C' access.log
```

### Command Line Options

- `--log-format`: Apache log format (default: combined)
- `--host`: Host to bind web server (default: 127.0.0.1)
- `--port`: Port for web server (default: 8000)
- `--mode`: Interface mode - `explorer` or `dashboard` (default: explorer)
- `--min-suspicious-requests`: Minimum requests to flag as suspicious (default: 100)

### Web Interface

After starting the tool, open your browser to `http://localhost:8000` to access:

#### Explorer Mode (Default)
- **Column Analysis**: Interactive overview of all log columns with statistics
- **Drill-Down Analysis**: Select multiple columns for detailed group analysis
- **Time Filtering**: Filter analysis by custom time windows
- **Anomaly Detection**: Real-time security alerts and recommendations
- **Interactive Charts**: Dynamic visualizations based on selected data

#### Dashboard Mode
- **Top IP Addresses**: Bar chart of highest traffic sources
- **Status Code Distribution**: Pie chart of HTTP response codes
- **Hourly Request Patterns**: Time series of request volume
- **Suspicious Activity Detection**: Table of potential abuse patterns
- **User Agent Analysis**: Analysis of bot and automated traffic

### API Endpoints

#### Explorer Mode
- `GET /`: Main data explorer interface
- `GET /api/columns`: Column metadata and statistics
- `GET /api/time-range`: Dataset time range information
- `GET /api/analyze-group`: Group analysis with time filtering
- `GET /api/anomalies`: Advanced anomaly detection alerts
- `GET /api/security-summary`: Comprehensive security overview
- `GET /api/column/{name}/distribution`: Single column distribution analysis

#### Dashboard Mode
- `GET /`: Traditional dashboard
- `GET /api/top-ips`: Top IP addresses by request count
- `GET /api/status-codes`: HTTP status code distribution
- `GET /api/hourly-requests`: Hourly request patterns
- `GET /api/suspicious-requests`: Suspicious activity detection
- `GET /api/user-agents`: User agent analysis
- `GET /api/abuse-patterns`: Detailed abuse pattern detection
- `GET /api/top-threats`: Top security threats by severity

## Log Formats

The tool supports three types of log format specifications:

### 1. Predefined Format Names

- **common**: Basic Apache Common Log Format
- **combined**: Apache Combined Log Format (includes referer and user agent)
- **combined_with_time**: Combined format with request processing time
- **vhost_combined**: Combined format with virtual host information

### 2. Apache LogFormat Strings

Use standard Apache LogFormat directives:

```bash
# Combined log format
a2logviz --log-format '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"' access.log

# Common log format with response time
a2logviz --log-format '%h %l %u %t "%r" %>s %O %D' access.log

# Virtual host combined format
a2logviz --log-format '%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"' access.log
```

Commonly used LogFormat directives:

- `%h`: Remote hostname/IP
- `%l`: Remote logname
- `%u`: Remote user
- `%t`: Time the request was received
- `%r`: First line of request
- `%>s`: Final status code
- `%O`: Bytes sent including headers
- `%{Header}i`: Request header (e.g., `%{Referer}i`, `%{User-Agent}i`)
- `%D`: Request processing time in microseconds
- `%T`: Request processing time in seconds
- `%v`: Canonical server name
- `%p`: Canonical port number

### 3. Custom Regex Patterns

You can specify a custom regex pattern with named groups:

```bash
a2logviz --log-format "(?P<remote_host>\S+) (?P<remote_logname>\S+) (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] \"(?P<request_line>[^\"]*)\\" (?P<status_code>\d+) (?P<response_size>\S+)" logs.txt
```

Required named groups for regex:

- `remote_host`: Client IP address
- `timestamp`: Request timestamp
- `request_line`: HTTP request line
- `status_code`: HTTP response code

Optional groups:

- `remote_logname`, `remote_user`, `response_size`, `referer`, `user_agent`, `request_time`

## Abuse Detection

### Brute Force Detection

Identifies IPs with high error rates in concentrated time periods:

- Minimum failed attempts threshold
- Error rate percentage
- Time window analysis

### DDoS Pattern Detection

Finds IPs generating high request volumes with low path diversity:

- Request volume thresholds
- Path diversity analysis
- Success rate monitoring

### Vulnerability Scanning

Detects directory and file scanning behavior:

- High 404 error rates
- Diverse path exploration patterns
- Bot-like request patterns

### Bot Behavior Analysis

Identifies automated traffic based on:

- User agent string analysis
- Request pattern anomalies
- IP/User-Agent correlation

## Development

### Setup Development Environment

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run type checking
mypy a2logviz/

# Run linting
ruff check a2logviz/

# Format code
black a2logviz/
```

### Testing Parser

```bash
# Test log parsing without starting server
python -m a2logviz.main test-parser access.log
```

## Requirements

- Python 3.9+
- ClickHouse Local
- Dependencies listed in pyproject.toml

## License

This project is released under the MIT License.
