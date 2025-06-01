"""Web server for Apache log visualization dashboard."""

from pathlib import Path
from typing import Any, Optional

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
    <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-timeline-graph2d.min.css" rel="stylesheet" type="text/css" />
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

        <div id="timeline-container" style="margin-bottom: 20px; min-height: 150px; border: 3px solid red; padding: 5px;">
            <!-- Timeline will be rendered here -->
            <p>Timeline Placeholder</p>
        </div>

        <div class="row mb-3" style="display: none;">
            <div class="col-md-5">
                <label for="start_time" class="form-label">Start Time:</label>
                <input type="datetime-local" id="start_time" name="start_time" class="form-control">
            </div>
            <div class="col-md-5">
                <label for="end_time" class="form-label">End Time:</label>
                <input type="datetime-local" id="end_time" name="end_time" class="form-control">
            </div>
            <div class="col-md-2 d-flex align-items-end">
                <button id="filter-button" class="btn btn-primary w-100">Filter</button>
            </div>
        </div>

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

    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-timeline-graph2d.min.js"></script>
    <script>
        // Load charts when page loads
        window.onload = function() {
            initializeTimeline(); // Initialize timeline first
            loadCharts(); // Load initial charts

            // Add event listener for the filter button
            const filterButton = document.getElementById('filter-button');
            if (filterButton) {
                filterButton.addEventListener('click', function() {
                    loadCharts(); // Reload charts with current time range
                });
            }
        };

        function initializeTimeline() {
            console.log('Attempting to initialize timeline...');
            const container = document.getElementById('timeline-container');
            console.log('Timeline container element:', container);
            if (!container) {
                console.error('Timeline container not found');
                return;
            }
            // Clear placeholder
            container.innerHTML = '';

            // Create a sample dataset (replace with actual data later)
            const items = new vis.DataSet([
                {id: 1, content: 'Event 1', start: new Date(new Date().getTime() - 60 * 60 * 1000)}, // 1 hour ago
                {id: 2, content: 'Event 2', start: new Date()}, // now
                {id: 3, content: 'Event 3', start: new Date(new Date().getTime() + 60 * 60 * 1000)}  // 1 hour from now
            ]);
            console.log('Vis DataSet created:', items);

            // Configuration for the Timeline
            const options = {
                selectable: true,
                multiselect: false,
                showCurrentTime: true,
                zoomable: true,
                // Ensure the range selection handles are visible
                showMajorLabels: true,
                showMinorLabels: true,
                // Allow dragging the selected range
                moveable: true,
            };
            console.log('Vis options set:', options);

            try {
                console.log('Attempting to create vis.Timeline object...');
                const timeline = new vis.Timeline(container, items, options);
                console.log('vis.Timeline object created:', timeline);

                timeline.on('rangechanged', function (properties) {
                    const startTimeInput = document.getElementById('start_time');
                    const endTimeInput = document.getElementById('end_time');

                    if (startTimeInput && endTimeInput) {
                        // Format to YYYY-MM-DDTHH:mm
                        const startStr = properties.start.toISOString().slice(0,16);
                        const endStr = properties.end.toISOString().slice(0,16);

                        startTimeInput.value = startStr;
                        endTimeInput.value = endStr;
                        console.log('Selected range:', startStr, endStr); // Existing log
                    }
                    console.log('Timeline rangechanged event:', properties); // New log for the event
                });
                console.log('rangechanged event listener attached.');

                const end = new Date();
                const start = new Date(end.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
                timeline.setWindow(start, end);
                console.log('Initial timeline window set.');

            } catch (error) {
                console.error('ERROR INITIALIZING VIS.JS TIMELINE:', error);
                if (container) {
                    container.innerHTML = '<p style="color: red; font-weight: bold;">Error initializing timeline. Check console.</p>';
                }
            }
        }

        async function loadCharts() {
            const startTimeElem = document.getElementById('start_time');
            const endTimeElem = document.getElementById('end_time');
            let queryParams = '';

            if (startTimeElem && endTimeElem && startTimeElem.value && endTimeElem.value) {
                const startTime = startTimeElem.value;
                const endTime = endTimeElem.value;
                queryParams = `?start_time=${encodeURIComponent(startTime)}&end_time=${encodeURIComponent(endTime)}`;
                console.log("Loading charts with time range:", queryParams);
            } else {
                console.log("Loading charts without time range.");
            }

            try {
                // Load top IPs chart
                const topIpsResponse = await fetch(`/api/top-ips${queryParams}`);
                const topIpsData = await topIpsResponse.json();
                renderTopIpsChart(topIpsData);

                // Load status codes chart
                const statusCodesResponse = await fetch(`/api/status-codes${queryParams}`);
                const statusCodesData = await statusCodesResponse.json();
                renderStatusCodesChart(statusCodesData);

                // Load hourly requests chart
                const hourlyResponse = await fetch(`/api/hourly-requests${queryParams}`);
                const hourlyData = await hourlyResponse.json();
                renderHourlyRequestsChart(hourlyData);

                // Load suspicious requests
                const suspiciousResponse = await fetch(`/api/suspicious-requests${queryParams}`);
                const suspiciousData = await suspiciousResponse.json();
                renderSuspiciousRequestsTable(suspiciousData);

                // Load user agents
                const userAgentsResponse = await fetch(`/api/user-agents${queryParams}`);
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
        async def get_top_ips(start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict[str, Any]]:
            """Get top IP addresses by request count."""
            return self.clickhouse.get_top_ips(start_time=start_time, end_time=end_time)

        @self.app.get("/api/status-codes")
        async def get_status_codes(start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict[str, Any]]:
            """Get HTTP status code distribution."""
            return self.clickhouse.get_status_code_distribution(start_time=start_time, end_time=end_time)

        @self.app.get("/api/hourly-requests")
        async def get_hourly_requests(start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict[str, Any]]:
            """Get hourly request patterns."""
            return self.clickhouse.get_hourly_requests(start_time=start_time, end_time=end_time)

        @self.app.get("/api/suspicious-requests")
        async def get_suspicious_requests(start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict[str, Any]]:
            """Get potentially suspicious request patterns."""
            return self.clickhouse.get_suspicious_requests(start_time=start_time, end_time=end_time)

        @self.app.get("/api/user-agents")
        async def get_user_agents(start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict[str, Any]]:
            """Get user agent analysis."""
            return self.clickhouse.get_user_agent_analysis(start_time=start_time, end_time=end_time)

        @self.app.get("/api/test")
        async def test_clickhouse(start_time: Optional[str] = None, end_time: Optional[str] = None) -> dict[str, Any]:
            """Test ClickHouse functionality."""
            return self.clickhouse.test_query(start_time=start_time, end_time=end_time)

    def get_app(self) -> FastAPI:
        """Get the FastAPI application instance."""
        return self.app
