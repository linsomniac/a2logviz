"""ClickHouse Local client for log data processing."""

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from clickhouse_driver import Client


class ClickHouseLocalClient:
    """Client for ClickHouse Local operations."""

    def __init__(self, database: str = "default") -> None:
        """Initialize ClickHouse Local client.

        Args:
            database: Database name to use
        """
        self.database = database
        self.temp_dir = Path(tempfile.mkdtemp(prefix="a2logviz_"))
        self.data_file = self.temp_dir / "access_logs.csv"
        self.client: Optional[Client] = None

    def _ensure_clickhouse_local(self) -> bool:
        """Check if clickhouse-local is available."""
        try:
            result = subprocess.run(
                ["clickhouse-local", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            return "ClickHouse" in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def setup_database(self, df: pd.DataFrame) -> None:
        """Set up ClickHouse Local with log data.

        Args:
            df: DataFrame containing parsed log data
        """
        if not self._ensure_clickhouse_local():
            raise RuntimeError(
                "clickhouse-local not found. Please install ClickHouse: "
                "https://clickhouse.com/docs/en/getting-started/install"
            )

        # Save DataFrame to CSV
        df.to_csv(self.data_file, index=False)

        # Create table schema and store column info
        self.df_columns = list(df.columns)
        self.csv_schema = self._generate_csv_schema(df)
        self._generate_schema(df)

        # Initialize client (using clickhouse-local via subprocess for simplicity)
        self.client = Client("localhost")

        print(f"Setting up ClickHouse Local database with {len(df)} records...")
        print(f"Data saved to: {self.data_file}")
        print(f"CSV columns: {list(df.columns)}")

        # Debug: show first few rows of CSV
        print("First 3 rows of CSV:")
        with open(self.data_file, "r") as f:
            for i, line in enumerate(f):
                if i < 3:
                    print(f"  {line.strip()}")
                else:
                    break

    def _generate_schema(self, df: pd.DataFrame) -> str:
        """Generate ClickHouse table schema from DataFrame."""
        type_mapping = {
            "object": "String",
            "int64": "Int64",
            "float64": "Float64",
            "datetime64[ns]": "DateTime",
            "datetime64[ns, UTC]": "DateTime",
            "bool": "UInt8",
        }

        columns = []
        for col, dtype in df.dtypes.items():
            ch_type = type_mapping.get(str(dtype), "String")
            columns.append(f"{col} {ch_type}")

        return f"CREATE TABLE IF NOT EXISTS access_logs ({', '.join(columns)}) ENGINE = Memory"

    def _generate_csv_schema(self, df: pd.DataFrame) -> str:
        """Generate CSV schema string for ClickHouse file() function."""
        type_mapping = {
            "object": "String",
            "int64": "Int64",
            "float64": "Float64",
            "datetime64[ns]": "DateTime",
            "datetime64[ns, UTC]": "DateTime",
            "bool": "UInt8",
        }

        columns = []
        for col, dtype in df.dtypes.items():
            ch_type = type_mapping.get(str(dtype), "String")
            # Make most columns nullable except for key fields
            if col in ["remote_host", "timestamp", "request_line", "status_code"]:
                columns.append(f"{col} {ch_type}")
            else:
                columns.append(f"{col} Nullable({ch_type})")

        return ", ".join(columns)

    def execute_query(
        self, query: str, expected_columns: list[str] = None
    ) -> list[dict[str, Any]]:
        """Execute a query against the log data.

        Args:
            query: Complete SQL query to execute
            expected_columns: List of expected column names for result parsing

        Returns:
            Query results as list of dictionaries
        """
        try:
            # Add JSON output format for easier parsing
            full_query = f"{query} FORMAT JSONEachRow"

            result = subprocess.run(
                ["clickhouse-local", "--query", full_query],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse JSON output
            lines = result.stdout.strip().split("\n")
            if not lines or not lines[0]:
                return []

            data = []
            for line in lines:
                if line.strip():
                    try:
                        import json

                        row = json.loads(line)
                        data.append(row)
                    except json.JSONDecodeError:
                        continue

            return data
        except subprocess.CalledProcessError as e:
            print(f"Query failed: {e}")
            print(f"Error output: {e.stderr}")
            print(f"Query was: {query}")
            return []

    def get_top_ips(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get top IP addresses by request count."""
        query = f"""
        SELECT
            remote_host as ip,
            count() as request_count
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        GROUP BY remote_host 
        ORDER BY request_count DESC 
        LIMIT {limit}
        """
        return self.execute_query(query)

    def get_status_code_distribution(self) -> list[dict[str, Any]]:
        """Get distribution of HTTP status codes."""
        query = f"""
        SELECT
            status_code,
            count() as count
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        GROUP BY status_code 
        ORDER BY status_code
        """
        return self.execute_query(query)

    def get_hourly_requests(self) -> list[dict[str, Any]]:
        """Get request count by hour."""
        query = f"""
        SELECT
            toHour(timestamp) as hour,
            count() as request_count
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        GROUP BY hour 
        ORDER BY hour
        """
        return self.execute_query(query)

    def get_suspicious_requests(self, min_requests: int = 100) -> list[dict[str, Any]]:
        """Identify potentially suspicious request patterns."""
        query = f"""
        SELECT
            remote_host as ip,
            count() as request_count,
            countIf(status_code >= 400) as error_count,
            countIf(status_code = 404) as not_found_count,
            uniq(path) as unique_paths
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        GROUP BY remote_host 
        HAVING request_count >= {min_requests} 
        ORDER BY request_count DESC
        """
        return self.execute_query(query)

    def get_user_agent_analysis(self) -> list[dict[str, Any]]:
        """Analyze user agent patterns for bot detection."""
        query = f"""
        SELECT
            user_agent,
            count() as request_count,
            uniq(remote_host) as unique_ips
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        WHERE user_agent IS NOT NULL AND user_agent != ''
        GROUP BY user_agent 
        ORDER BY request_count DESC 
        LIMIT 20
        """
        return self.execute_query(query)

    def test_query(self) -> dict[str, Any]:
        """Test basic query functionality."""
        query = f"""
        SELECT 
            count() as total_rows,
            uniq(remote_host) as unique_ips,
            min(timestamp) as earliest_request,
            max(timestamp) as latest_request
        FROM file('{self.data_file}', CSV, '{self.csv_schema}')
        """
        result = self.execute_query(query)
        return result[0] if result else {}

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.data_file.exists():
            self.data_file.unlink()
        if self.temp_dir.exists():
            self.temp_dir.rmdir()
