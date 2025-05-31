"""Advanced data exploration web server for Apache log analysis."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .clickhouse_client import ClickHouseLocalClient
from .column_analyzer import ColumnAnalyzer


class ExplorationServer:
    """Advanced web server for data exploration and anomaly detection."""

    def __init__(self, clickhouse_client: ClickHouseLocalClient):
        """Initialize the exploration server.

        Args:
            clickhouse_client: ClickHouse client with loaded log data
        """
        self.app = FastAPI(title="Apache Log Explorer", version="0.1.0")
        self.clickhouse = clickhouse_client
        self.analyzer = ColumnAnalyzer(clickhouse_client)
        self.templates = Jinja2Templates(directory="templates")

        # Create templates directory if it doesn't exist
        templates_dir = Path("templates")
        templates_dir.mkdir(exist_ok=True)
        self._create_templates()

        # Analyze columns on initialization
        self.column_metadata = self.analyzer.analyze_all_columns()
        self.time_range = self.analyzer.get_time_range()

        self._setup_routes()

    def _create_templates(self) -> None:
        """Create HTML templates for the exploration interface."""
        # Main exploration page
        exploration_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Apache Log Explorer</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .column-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            cursor: pointer;
            transition: all 0.2s;
        }
        .column-card:hover {
            border-color: #007bff;
            box-shadow: 0 2px 4px rgba(0,123,255,0.1);
        }
        .column-card.selected {
            border-color: #007bff;
            background-color: #f8f9ff;
        }
        .anomaly-high { border-left: 4px solid #dc3545; }
        .anomaly-medium { border-left: 4px solid #ffc107; }
        .anomaly-low { border-left: 4px solid #28a745; }
        .stat-badge {
            display: inline-block;
            padding: 2px 8px;
            margin: 2px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
        }
        .badge-categorical { background-color: #e3f2fd; color: #1976d2; }
        .badge-numerical { background-color: #f3e5f5; color: #7b1fa2; }
        .badge-temporal { background-color: #e8f5e8; color: #388e3c; }
        .badge-text { background-color: #fff3e0; color: #f57c00; }
        .filter-panel {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .drill-down-panel {
            background-color: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        #columnGrid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        .chart-container {
            margin: 20px 0;
            min-height: 400px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <h1 class="mt-4 mb-4">Apache Log Data Explorer</h1>
        
        <!-- Time Range Filter -->
        <div class="filter-panel">
            <h4>Time Range Filter</h4>
            <div class="row">
                <div class="col-md-3">
                    <label for="startTime" class="form-label">Start Time</label>
                    <input type="datetime-local" class="form-control" id="startTime">
                </div>
                <div class="col-md-3">
                    <label for="endTime" class="form-label">End Time</label>
                    <input type="datetime-local" class="form-control" id="endTime">
                </div>
                <div class="col-md-3">
                    <label class="form-label">&nbsp;</label>
                    <div>
                        <button class="btn btn-primary" onclick="applyTimeFilter()">Apply Filter</button>
                        <button class="btn btn-secondary" onclick="clearTimeFilter()">Clear</button>
                    </div>
                </div>
                <div class="col-md-3">
                    <small class="text-muted">
                        Data Range: <span id="dataRange">Loading...</span>
                    </small>
                </div>
            </div>
        </div>

        <!-- Column Selection -->
        <div class="row">
            <div class="col-md-8">
                <h3>Available Columns <small class="text-muted">(Click to select for analysis)</small></h3>
                <div id="columnGrid">
                    <!-- Columns will be populated here -->
                </div>
            </div>
            <div class="col-md-4">
                <div class="sticky-top" style="top: 20px;">
                    <h4>Selected Columns</h4>
                    <div id="selectedColumns" class="mb-3">
                        <p class="text-muted">No columns selected</p>
                    </div>
                    <button class="btn btn-success" onclick="analyzeSelection()" disabled id="analyzeBtn">
                        Analyze Selected Columns
                    </button>
                    <button class="btn btn-secondary ms-2" onclick="clearSelection()">Clear</button>
                </div>
            </div>
        </div>

        <!-- Drill-down Results -->
        <div id="drillDownResults" class="drill-down-panel" style="display: none;">
            <h3>Analysis Results</h3>
            <div id="analysisContent">
                <!-- Analysis results will be shown here -->
            </div>
        </div>
    </div>

    <script>
        let selectedColumns = [];
        let columnMetadata = {};
        let currentTimeFilter = null;

        // Load initial data
        window.onload = function() {
            loadColumnMetadata();
            loadTimeRange();
        };

        async function loadColumnMetadata() {
            try {
                const response = await fetch('/api/columns');
                columnMetadata = await response.json();
                renderColumns();
            } catch (error) {
                console.error('Error loading column metadata:', error);
            }
        }

        async function loadTimeRange() {
            try {
                const response = await fetch('/api/time-range');
                const timeRange = await response.json();
                document.getElementById('dataRange').textContent = 
                    `${timeRange.earliest} to ${timeRange.latest}`;
                
                // Set default time range in inputs
                if (timeRange.earliest !== 'Unknown') {
                    document.getElementById('startTime').value = 
                        new Date(timeRange.earliest).toISOString().slice(0, 16);
                }
                if (timeRange.latest !== 'Unknown') {
                    document.getElementById('endTime').value = 
                        new Date(timeRange.latest).toISOString().slice(0, 16);
                }
            } catch (error) {
                console.error('Error loading time range:', error);
            }
        }

        function renderColumns() {
            const grid = document.getElementById('columnGrid');
            grid.innerHTML = '';

            Object.values(columnMetadata).forEach(column => {
                const card = createColumnCard(column);
                grid.appendChild(card);
            });
        }

        function createColumnCard(column) {
            const card = document.createElement('div');
            card.className = `column-card ${getAnomalyClass(column.anomaly_score)}`;
            card.onclick = () => toggleColumnSelection(column.name);
            
            const typeClass = `badge-${column.analysis_type}`;
            const mostCommon = column.most_common && column.most_common.length > 0 
                ? column.most_common[0] : null;
            
            card.innerHTML = `
                <h5>${column.name}</h5>
                <div class="mb-2">
                    <span class="stat-badge ${typeClass}">${column.analysis_type}</span>
                    <span class="stat-badge badge-secondary">${column.data_type}</span>
                </div>
                <div class="row text-center">
                    <div class="col-4">
                        <strong>${column.cardinality.toLocaleString()}</strong><br>
                        <small>Unique Values</small>
                    </div>
                    <div class="col-4">
                        <strong>${column.total_count.toLocaleString()}</strong><br>
                        <small>Total Records</small>
                    </div>
                    <div class="col-4">
                        <strong>${(column.null_count / column.total_count * 100).toFixed(1)}%</strong><br>
                        <small>Null/Empty</small>
                    </div>
                </div>
                ${mostCommon ? `
                <div class="mt-2">
                    <small><strong>Most Common:</strong> ${mostCommon.value} (${mostCommon.frequency.toLocaleString()} times)</small>
                </div>
                ` : ''}
                <div class="mt-2">
                    <small><strong>Sample:</strong> ${column.sample_values.slice(0, 3).join(', ')}</small>
                </div>
                ${column.anomaly_score > 0.3 ? `
                <div class="mt-2">
                    <small class="text-warning"><strong>⚠ Anomaly Score:</strong> ${(column.anomaly_score * 100).toFixed(0)}%</small>
                </div>
                ` : ''}
            `;
            
            return card;
        }

        function getAnomalyClass(score) {
            if (score > 0.6) return 'anomaly-high';
            if (score > 0.3) return 'anomaly-medium';
            return 'anomaly-low';
        }

        function toggleColumnSelection(columnName) {
            const index = selectedColumns.indexOf(columnName);
            if (index > -1) {
                selectedColumns.splice(index, 1);
            } else {
                selectedColumns.push(columnName);
            }
            updateSelectedColumnsDisplay();
            updateColumnCardSelection();
        }

        function updateSelectedColumnsDisplay() {
            const container = document.getElementById('selectedColumns');
            const analyzeBtn = document.getElementById('analyzeBtn');
            
            if (selectedColumns.length === 0) {
                container.innerHTML = '<p class="text-muted">No columns selected</p>';
                analyzeBtn.disabled = true;
            } else {
                container.innerHTML = selectedColumns.map(col => 
                    `<span class="badge bg-primary me-1 mb-1">${col}</span>`
                ).join('');
                analyzeBtn.disabled = false;
            }
        }

        function updateColumnCardSelection() {
            document.querySelectorAll('.column-card').forEach(card => {
                const columnName = card.querySelector('h5').textContent;
                if (selectedColumns.includes(columnName)) {
                    card.classList.add('selected');
                } else {
                    card.classList.remove('selected');
                }
            });
        }

        function clearSelection() {
            selectedColumns = [];
            updateSelectedColumnsDisplay();
            updateColumnCardSelection();
            document.getElementById('drillDownResults').style.display = 'none';
        }

        function applyTimeFilter() {
            const startTime = document.getElementById('startTime').value;
            const endTime = document.getElementById('endTime').value;
            
            if (startTime && endTime) {
                currentTimeFilter = {
                    start: startTime.replace('T', ' ') + ':00',
                    end: endTime.replace('T', ' ') + ':00'
                };
            } else {
                currentTimeFilter = null;
            }
        }

        function clearTimeFilter() {
            document.getElementById('startTime').value = '';
            document.getElementById('endTime').value = '';
            currentTimeFilter = null;
        }

        async function analyzeSelection() {
            if (selectedColumns.length === 0) return;
            
            const resultsPanel = document.getElementById('drillDownResults');
            const contentDiv = document.getElementById('analysisContent');
            
            resultsPanel.style.display = 'block';
            contentDiv.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p>Analyzing selected columns...</p></div>';
            
            try {
                const params = new URLSearchParams({
                    columns: selectedColumns.join(','),
                    limit: '50'
                });
                
                if (currentTimeFilter) {
                    params.append('start_time', currentTimeFilter.start);
                    params.append('end_time', currentTimeFilter.end);
                }
                
                const response = await fetch(`/api/analyze-group?${params}`);
                const analysis = await response.json();
                
                renderAnalysisResults(analysis);
                
            } catch (error) {
                contentDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
            }
        }

        function renderAnalysisResults(analysis) {
            const contentDiv = document.getElementById('analysisContent');
            
            if (analysis.error) {
                contentDiv.innerHTML = `<div class="alert alert-danger">${analysis.error}</div>`;
                return;
            }
            
            let html = `
                <div class="row mb-3">
                    <div class="col-md-12">
                        <h4>Group Analysis: ${analysis.columns.join(', ')}</h4>
                        <p class="text-muted">Found ${analysis.total_groups} unique combinations</p>
                    </div>
                </div>
            `;
            
            if (analysis.groups && analysis.groups.length > 0) {
                // Create table
                html += `
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                `;
                
                // Add column headers
                analysis.columns.forEach(col => {
                    html += `<th>${col}</th>`;
                });
                html += `<th>Frequency</th><th>Percentage</th></tr></thead><tbody>`;
                
                // Add data rows
                analysis.groups.forEach(group => {
                    html += '<tr>';
                    analysis.columns.forEach(col => {
                        const value = group[col] || 'N/A';
                        const displayValue = value.length > 50 ? value.substring(0, 50) + '...' : value;
                        html += `<td title="${value}">${displayValue}</td>`;
                    });
                    html += `<td><strong>${group.frequency.toLocaleString()}</strong></td>`;
                    html += `<td>${group.percentage.toFixed(2)}%</td>`;
                    html += '</tr>';
                });
                
                html += '</tbody></table></div>';
                
                // Add visualization
                html += '<div id="groupChart" class="chart-container"></div>';
                
                contentDiv.innerHTML = html;
                
                // Create chart
                createGroupChart(analysis);
                
            } else {
                html += '<div class="alert alert-info">No data found for the selected criteria.</div>';
                contentDiv.innerHTML = html;
            }
        }

        function createGroupChart(analysis) {
            if (!analysis.groups || analysis.groups.length === 0) return;
            
            // Create frequency chart
            const data = analysis.groups.slice(0, 20); // Top 20 only
            const labels = data.map(group => {
                return analysis.columns.map(col => {
                    const val = group[col] || 'N/A';
                    return val.length > 20 ? val.substring(0, 20) + '...' : val;
                }).join(' | ');
            });
            
            const trace = {
                x: labels,
                y: data.map(group => group.frequency),
                type: 'bar',
                marker: {
                    color: data.map(group => group.percentage),
                    colorscale: 'Viridis',
                    showscale: true,
                    colorbar: {title: 'Percentage'}
                }
            };
            
            const layout = {
                title: `Top ${Math.min(data.length, 20)} Combinations by Frequency`,
                xaxis: {
                    title: 'Combinations',
                    tickangle: -45
                },
                yaxis: {title: 'Frequency'},
                margin: {b: 150}
            };
            
            Plotly.newPlot('groupChart', [trace], layout);
        }
    </script>
</body>
</html>
        """

        with open("templates/explorer.html", "w") as f:
            f.write(exploration_html)

    def _setup_routes(self) -> None:
        """Set up API routes for the exploration server."""

        @self.app.get("/", response_class=HTMLResponse)
        async def explorer_dashboard(request: Request) -> HTMLResponse:
            """Serve the main exploration page."""
            return self.templates.TemplateResponse(
                "explorer.html", {"request": request}
            )

        @self.app.get("/api/columns")
        async def get_columns() -> Dict[str, Any]:
            """Get column metadata for all columns."""
            return {
                col_name: {
                    "name": metadata.name,
                    "data_type": metadata.data_type,
                    "cardinality": metadata.cardinality,
                    "null_count": metadata.null_count,
                    "total_count": metadata.total_count,
                    "sample_values": metadata.sample_values,
                    "min_value": metadata.min_value,
                    "max_value": metadata.max_value,
                    "avg_length": metadata.avg_length,
                    "most_common": metadata.most_common or [],
                    "anomaly_score": metadata.anomaly_score,
                    "analysis_type": metadata.analysis_type,
                }
                for col_name, metadata in self.column_metadata.items()
            }

        @self.app.get("/api/time-range")
        async def get_time_range() -> Dict[str, str]:
            """Get the time range of the dataset."""
            return self.time_range

        @self.app.get("/api/analyze-group")
        async def analyze_column_group(
            columns: str = Query(..., description="Comma-separated list of columns"),
            start_time: Optional[str] = Query(None, description="Start time filter"),
            end_time: Optional[str] = Query(None, description="End time filter"),
            limit: int = Query(50, description="Maximum number of results"),
        ) -> Dict[str, Any]:
            """Analyze a group of columns with optional time filtering."""
            column_list = [col.strip() for col in columns.split(",")]

            time_filter = None
            if start_time and end_time:
                time_filter = {"start": start_time, "end": end_time}

            return self.analyzer.analyze_column_group(column_list, time_filter, limit)

        @self.app.get("/api/column/{column_name}/distribution")
        async def get_column_distribution(
            column_name: str,
            start_time: Optional[str] = Query(None),
            end_time: Optional[str] = Query(None),
            limit: int = Query(100),
        ) -> Dict[str, Any]:
            """Get detailed distribution analysis for a single column."""
            time_filter = None
            if start_time and end_time:
                time_filter = {"start": start_time, "end": end_time}

            # Build time condition
            time_condition = ""
            if time_filter:
                timestamp_col = next(
                    (
                        col
                        for col in self.column_metadata.keys()
                        if "timestamp" in col.lower()
                    ),
                    None,
                )
                if timestamp_col:
                    time_condition = f"AND {timestamp_col} BETWEEN '{time_filter['start']}' AND '{time_filter['end']}'"

            try:
                # Get distribution
                query = f"""
                SELECT
                    {column_name} as value,
                    count() as frequency,
                    count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE {column_name} IS NOT NULL {time_condition}) as percentage
                FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
                WHERE {column_name} IS NOT NULL AND {column_name} != '' {time_condition}
                GROUP BY {column_name}
                ORDER BY frequency DESC
                LIMIT {limit}
                """

                result = self.clickhouse.execute_query(query)
                return {
                    "column": column_name,
                    "distribution": result,
                    "time_filter": time_filter,
                }

            except Exception as e:
                return {"error": str(e)}

    def get_app(self) -> FastAPI:
        """Get the FastAPI application instance."""
        return self.app
