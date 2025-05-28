"""Web server for Apache log visualization dashboard."""

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .clickhouse_client import ClickHouseLocalClient


class LogVisualizationServer:
    """Web server for log visualization dashboard."""

    def __init__(self, clickhouse_client: ClickHouseLocalClient) -> None:
        """Initialize the web server.

        Args:
            clickhouse_client: ClickHouse client with loaded log data
        """
        self.app = FastAPI(title="Apache Log Visualizer", version="0.1.0")
        self.clickhouse = clickhouse_client
        self.templates = Jinja2Templates(directory="templates")

        # Create templates directory if it doesn't exist
        templates_dir = Path("templates")
        templates_dir.mkdir(exist_ok=True)
        self._create_templates()

        self._setup_routes()

    def _create_templates(self) -> None:
        """Create HTML templates for the dashboard."""
        # Main dashboard template
        dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Apache Log Visualizer</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .chart-container { margin: 20px 0; }
        .metric-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <h1 class="mt-4 mb-4">Apache Log Analysis Dashboard</h1>

        <div class="row">
            <div class="col-md-6">
                <div class="metric-card">
                    <h3>Top IP Addresses</h3>
                    <div id="top-ips-chart"></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="metric-card">
                    <h3>Status Code Distribution</h3>
                    <div id="status-codes-chart"></div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="metric-card">
                    <h3>Hourly Request Pattern</h3>
                    <div id="hourly-requests-chart"></div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="metric-card">
                    <h3>Suspicious Activity Detection</h3>
                    <div id="suspicious-requests-table"></div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="metric-card">
                    <h3>User Agent Analysis</h3>
                    <div id="user-agents-table"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Load charts when page loads
        window.onload = function() {
            loadCharts();
        };

        async function loadCharts() {
            try {
                // Load top IPs chart
                const topIpsResponse = await fetch('/api/top-ips');
                const topIpsData = await topIpsResponse.json();
                renderTopIpsChart(topIpsData);

                // Load status codes chart
                const statusCodesResponse = await fetch('/api/status-codes');
                const statusCodesData = await statusCodesResponse.json();
                renderStatusCodesChart(statusCodesData);

                // Load hourly requests chart
                const hourlyResponse = await fetch('/api/hourly-requests');
                const hourlyData = await hourlyResponse.json();
                renderHourlyRequestsChart(hourlyData);

                // Load suspicious requests
                const suspiciousResponse = await fetch('/api/suspicious-requests');
                const suspiciousData = await suspiciousResponse.json();
                renderSuspiciousRequestsTable(suspiciousData);

                // Load user agents
                const userAgentsResponse = await fetch('/api/user-agents');
                const userAgentsData = await userAgentsResponse.json();
                renderUserAgentsTable(userAgentsData);

            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }

        function renderTopIpsChart(data) {
            const trace = {
                x: data.map(d => d.ip),
                y: data.map(d => parseInt(d.request_count)),
                type: 'bar',
                marker: { color: '#007bff' }
            };

            const layout = {
                title: 'Top IP Addresses by Request Count',
                xaxis: { title: 'IP Address' },
                yaxis: { title: 'Request Count' }
            };

            Plotly.newPlot('top-ips-chart', [trace], layout);
        }

        function renderStatusCodesChart(data) {
            const trace = {
                labels: data.map(d => d.status_code),
                values: data.map(d => parseInt(d.count)),
                type: 'pie'
            };

            const layout = {
                title: 'HTTP Status Code Distribution'
            };

            Plotly.newPlot('status-codes-chart', [trace], layout);
        }

        function renderHourlyRequestsChart(data) {
            const trace = {
                x: data.map(d => d.hour),
                y: data.map(d => parseInt(d.request_count)),
                type: 'scatter',
                mode: 'lines+markers',
                line: { color: '#28a745' }
            };

            const layout = {
                title: 'Request Volume by Hour',
                xaxis: { title: 'Hour of Day' },
                yaxis: { title: 'Request Count' }
            };

            Plotly.newPlot('hourly-requests-chart', [trace], layout);
        }

        function renderSuspiciousRequestsTable(data) {
            let html = `
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Total Requests</th>
                            <th>Error Count</th>
                            <th>404 Count</th>
                            <th>Unique Paths</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            data.forEach(row => {
                html += `
                    <tr>
                        <td>${row.ip}</td>
                        <td>${row.request_count}</td>
                        <td>${row.error_count}</td>
                        <td>${row.not_found_count}</td>
                        <td>${row.unique_paths}</td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            document.getElementById('suspicious-requests-table').innerHTML = html;
        }

        function renderUserAgentsTable(data) {
            let html = `
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>User Agent</th>
                            <th>Request Count</th>
                            <th>Unique IPs</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            data.slice(0, 10).forEach(row => {
                const userAgent = row.user_agent || 'Unknown';
                const truncatedUA = userAgent.length > 80 ? userAgent.substring(0, 80) + '...' : userAgent;
                html += `
                    <tr>
                        <td title="${userAgent}">${truncatedUA}</td>
                        <td>${row.request_count}</td>
                        <td>${row.unique_ips}</td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            document.getElementById('user-agents-table').innerHTML = html;
        }
    </script>
</body>
</html>
        """

        with open("templates/dashboard.html", "w") as f:
            f.write(dashboard_html)

    def _setup_routes(self) -> None:
        """Set up API routes for the web server."""

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request) -> HTMLResponse:
            """Serve the main dashboard page."""
            return self.templates.TemplateResponse(
                "dashboard.html", {"request": request}
            )

        @self.app.get("/api/top-ips")
        async def get_top_ips() -> list[dict[str, Any]]:
            """Get top IP addresses by request count."""
            return self.clickhouse.get_top_ips()

        @self.app.get("/api/status-codes")
        async def get_status_codes() -> list[dict[str, Any]]:
            """Get HTTP status code distribution."""
            return self.clickhouse.get_status_code_distribution()

        @self.app.get("/api/hourly-requests")
        async def get_hourly_requests() -> list[dict[str, Any]]:
            """Get hourly request patterns."""
            return self.clickhouse.get_hourly_requests()

        @self.app.get("/api/suspicious-requests")
        async def get_suspicious_requests() -> list[dict[str, Any]]:
            """Get potentially suspicious request patterns."""
            return self.clickhouse.get_suspicious_requests()

        @self.app.get("/api/user-agents")
        async def get_user_agents() -> list[dict[str, Any]]:
            """Get user agent analysis."""
            return self.clickhouse.get_user_agent_analysis()

    def get_app(self) -> FastAPI:
        """Get the FastAPI application instance."""
        return self.app
