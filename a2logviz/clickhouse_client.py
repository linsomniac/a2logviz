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

        # Create table schema
        self._generate_schema(df)

        # Initialize client (using clickhouse-local via subprocess for simplicity)
        self.client = Client("localhost")

        print(f"Setting up ClickHouse Local database with {len(df)} records...")
        print(f"Data saved to: {self.data_file}")

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

    def execute_query(self, query: str) -> list[dict[str, Any]]:
        """Execute a query against the log data.

        Args:
            query: SQL query to execute

        Returns:
            Query results as list of dictionaries
        """
        # Use clickhouse-local for querying CSV directly
        full_query = f"""
        {query}
        FROM file('{self.data_file}', CSV, 'remote_host String, remote_logname Nullable(String), remote_user Nullable(String), timestamp DateTime, request_line String, status_code Int32, response_size Nullable(Int64), referer Nullable(String), user_agent Nullable(String), request_time Nullable(Float64), method String, path String, protocol String')
        """

        try:
            result = subprocess.run(
                ["clickhouse-local", "--query", full_query],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse tab-separated output
            lines = result.stdout.strip().split("\n")
            if not lines or not lines[0]:
                return []

            # Simple parsing - assumes tab-separated values
            headers = ["result"]  # Simplified for basic queries
            data = []
            for line in lines:
                if line.strip():
                    parts = line.split("\t")
                    data.append(dict(zip(headers, parts)))

            return data
        except subprocess.CalledProcessError as e:
            print(f"Query failed: {e}")
            print(f"Error output: {e.stderr}")
            return []

    def get_top_ips(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get top IP addresses by request count."""
        query = """
        SELECT
            remote_host as ip,
            count() as request_count
        FROM (SELECT * """

        result = self.execute_query(
            query + f") GROUP BY remote_host ORDER BY request_count DESC LIMIT {limit}"
        )
        return result

    def get_status_code_distribution(self) -> list[dict[str, Any]]:
        """Get distribution of HTTP status codes."""
        query = """
        SELECT
            status_code,
            count() as count
        FROM (SELECT * """

        result = self.execute_query(
            query + ") GROUP BY status_code ORDER BY status_code"
        )
        return result

    def get_hourly_requests(self) -> list[dict[str, Any]]:
        """Get request count by hour."""
        query = """
        SELECT
            toHour(timestamp) as hour,
            count() as request_count
        FROM (SELECT * """

        result = self.execute_query(query + ") GROUP BY hour ORDER BY hour")
        return result

    def get_suspicious_requests(self, min_requests: int = 100) -> list[dict[str, Any]]:
        """Identify potentially suspicious request patterns."""
        query = """
        SELECT
            remote_host as ip,
            count() as request_count,
            countIf(status_code >= 400) as error_count,
            countIf(status_code = 404) as not_found_count,
            uniq(path) as unique_paths
        FROM (SELECT * """

        result = self.execute_query(
            query
            + f") GROUP BY remote_host HAVING request_count >= {min_requests} ORDER BY request_count DESC"
        )
        return result

    def get_user_agent_analysis(self) -> list[dict[str, Any]]:
        """Analyze user agent patterns for bot detection."""
        query = """
        SELECT
            user_agent,
            count() as request_count,
            uniq(remote_host) as unique_ips
        FROM (SELECT * """

        result = self.execute_query(
            query + ") GROUP BY user_agent ORDER BY request_count DESC LIMIT 20"
        )
        return result

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.data_file.exists():
            self.data_file.unlink()
        if self.temp_dir.exists():
            self.temp_dir.rmdir()
