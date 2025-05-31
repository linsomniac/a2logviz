"""Column analysis and metadata extraction for log data."""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from .clickhouse_client import ClickHouseLocalClient


@dataclass
class ColumnMetadata:
    """Metadata about a column in the log data."""

    name: str
    data_type: str
    cardinality: int
    null_count: int
    total_count: int
    sample_values: List[str]
    min_value: Optional[str] = None
    max_value: Optional[str] = None
    avg_length: Optional[float] = None
    most_common: List[Dict[str, Any]] = None
    anomaly_score: float = 0.0
    analysis_type: str = "categorical"  # categorical, numerical, temporal, text


class ColumnAnalyzer:
    """Analyzes columns in log data for exploration and anomaly detection."""

    def __init__(self, clickhouse_client: ClickHouseLocalClient):
        """Initialize the column analyzer.

        Args:
            clickhouse_client: ClickHouse client with loaded log data
        """
        self.clickhouse = clickhouse_client
        self.column_metadata: Dict[str, ColumnMetadata] = {}

    def analyze_all_columns(self) -> Dict[str, ColumnMetadata]:
        """Analyze all columns in the dataset."""
        print("Analyzing all columns...")

        # Get basic column info
        columns_query = f"""
        SELECT *
        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
        LIMIT 1
        """

        try:
            sample_result = self.clickhouse.execute_query(columns_query)
            if not sample_result:
                return {}

            column_names = list(sample_result[0].keys())
            print(f"Found columns: {column_names}")

            # Analyze each column
            for column in column_names:
                try:
                    metadata = self._analyze_single_column(column)
                    self.column_metadata[column] = metadata
                    print(f"Analyzed column: {column}")
                except Exception as e:
                    print(f"Failed to analyze column {column}: {e}")
                    # Create minimal metadata for failed columns but try to get basic info
                    try:
                        # Try a simpler query to get at least total count
                        simple_query = f"""
                        SELECT count() as total_count
                        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
                        """
                        simple_result = self.clickhouse.execute_query(simple_query)
                        total_count = int(simple_result[0]["total_count"]) if simple_result else 1
                    except:
                        total_count = 1  # Set to 1 to ensure column appears in UI
                    
                    self.column_metadata[column] = ColumnMetadata(
                        name=column,
                        data_type="unknown",
                        cardinality=1,  # Set to 1 instead of 0 to ensure column appears
                        null_count=0,
                        total_count=total_count,
                        sample_values=["(analysis failed)"],
                        most_common=[],
                        anomaly_score=0.1,  # Small score to indicate needs attention
                    )

            return self.column_metadata

        except Exception as e:
            print(f"Failed to analyze columns: {e}")
            return {}

    def _analyze_single_column(self, column: str) -> ColumnMetadata:
        """Analyze a single column and return its metadata."""
        # Escape column name for SQL safety
        escaped_column = f'`{column}`' if not column.startswith('`') else column
        
        # Basic statistics query
        basic_stats_query = f"""
        SELECT
            count() as total_count,
            countIf({escaped_column} IS NULL OR {escaped_column} = '') as null_count,
            uniq({escaped_column}) as cardinality,
            any({escaped_column}) as sample_value
        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
        """

        basic_stats = self.clickhouse.execute_query(basic_stats_query)
        if not basic_stats:
            raise ValueError(f"Failed to get basic stats for {column}")

        stats = basic_stats[0]
        total_count = int(stats["total_count"])
        null_count = int(stats["null_count"])
        cardinality = int(stats["cardinality"])
        sample_value = stats["sample_value"]

        # Get sample values
        sample_query = f"""
        SELECT DISTINCT {escaped_column}
        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
        WHERE {escaped_column} IS NOT NULL AND {escaped_column} != ''
        LIMIT 10
        """

        sample_result = self.clickhouse.execute_query(sample_query)
        sample_values = [str(row[column]) for row in sample_result if row[column]]

        # Get most common values
        top_values_query = f"""
        SELECT
            {escaped_column} as value,
            count() as frequency,
            count() * 100.0 / {total_count} as percentage
        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
        WHERE {escaped_column} IS NOT NULL AND {escaped_column} != ''
        GROUP BY {escaped_column}
        ORDER BY frequency DESC
        LIMIT 10
        """

        top_values_result = self.clickhouse.execute_query(top_values_query)
        most_common = [
            {
                "value": str(row["value"]),
                "frequency": int(row["frequency"]),
                "percentage": float(row["percentage"]),
            }
            for row in top_values_result
        ]

        # Determine analysis type and additional stats
        analysis_type, min_val, max_val, avg_length = self._determine_column_type(
            column, escaped_column, sample_values, cardinality, total_count
        )

        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(
            cardinality, total_count, null_count, most_common
        )

        return ColumnMetadata(
            name=column,
            data_type=self._infer_data_type(sample_values),
            cardinality=cardinality,
            null_count=null_count,
            total_count=total_count,
            sample_values=sample_values,
            min_value=min_val,
            max_value=max_val,
            avg_length=avg_length,
            most_common=most_common,
            anomaly_score=anomaly_score,
            analysis_type=analysis_type,
        )

    def _determine_column_type(
        self, column: str, escaped_column: str, sample_values: List[str], cardinality: int, total_count: int
    ) -> tuple[str, Optional[str], Optional[str], Optional[float]]:
        """Determine the analysis type and additional statistics for a column."""
        min_val = None
        max_val = None
        avg_length = None

        # Check if it's a timestamp column
        if "timestamp" in column.lower() or "time" in column.lower():
            try:
                minmax_query = f"""
                SELECT
                    min({escaped_column}) as min_val,
                    max({escaped_column}) as max_val
                FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
                WHERE {escaped_column} IS NOT NULL
                """
                result = self.clickhouse.execute_query(minmax_query)
                if result:
                    min_val = str(result[0]["min_val"])
                    max_val = str(result[0]["max_val"])
                return "temporal", min_val, max_val, avg_length
            except:
                pass

        # Check if it's numeric based on sample values
        numeric_samples = 0
        for val in sample_values[:5]:
            try:
                float(val)
                numeric_samples += 1
            except:
                pass

        if numeric_samples >= len(sample_values) * 0.8 and sample_values:
            try:
                minmax_query = f"""
                SELECT
                    min(CAST({escaped_column} AS Float64)) as min_val,
                    max(CAST({escaped_column} AS Float64)) as max_val,
                    avg(length(toString({escaped_column}))) as avg_length
                FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
                WHERE {escaped_column} IS NOT NULL AND {escaped_column} != ''
                """
                result = self.clickhouse.execute_query(minmax_query)
                if result:
                    min_val = str(result[0]["min_val"])
                    max_val = str(result[0]["max_val"])
                    avg_length = float(result[0]["avg_length"])
                return "numerical", min_val, max_val, avg_length
            except:
                pass

        # Check if it's high-cardinality text (like URLs, user agents)
        if cardinality > total_count * 0.1:
            try:
                length_query = f"""
                SELECT avg(length({escaped_column})) as avg_length
                FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
                WHERE {escaped_column} IS NOT NULL AND {escaped_column} != ''
                """
                result = self.clickhouse.execute_query(length_query)
                if result:
                    avg_length = float(result[0]["avg_length"])
                return "text", min_val, max_val, avg_length
            except:
                pass

        # Default to categorical
        return "categorical", min_val, max_val, avg_length

    def _infer_data_type(self, sample_values: List[str]) -> str:
        """Infer the data type from sample values."""
        if not sample_values:
            return "unknown"

        # Check for IP addresses
        if any(
            len(val.split(".")) == 4 and all(part.isdigit() for part in val.split("."))
            for val in sample_values[:3]
        ):
            return "ip_address"

        # Check for URLs
        if any(
            val.startswith(("http://", "https://", "/")) for val in sample_values[:3]
        ):
            return "url"

        # Check for user agents
        if any(
            any(browser in val.lower() for browser in ["mozilla", "chrome", "safari"])
            for val in sample_values[:3]
        ):
            return "user_agent"

        # Check for numbers
        try:
            [float(val) for val in sample_values[:3]]
            return "numeric"
        except:
            pass

        return "string"

    def _calculate_anomaly_score(
        self,
        cardinality: int,
        total_count: int,
        null_count: int,
        most_common: List[Dict[str, Any]],
    ) -> float:
        """Calculate an anomaly score for the column."""
        score = 0.0

        # High cardinality might indicate interesting data
        cardinality_ratio = cardinality / max(total_count, 1)
        if cardinality_ratio > 0.5:
            score += 0.3

        # High null rate might indicate data quality issues
        null_ratio = null_count / max(total_count, 1)
        if null_ratio > 0.1:
            score += 0.2

        # Skewed distribution might indicate anomalies
        if most_common and len(most_common) > 1:
            top_percentage = most_common[0]["percentage"]
            if top_percentage > 80:
                score += 0.3  # Very skewed
            elif top_percentage < 5 and cardinality > 100:
                score += 0.2  # Very uniform with high cardinality

        return min(score, 1.0)

    def get_time_range(self) -> Dict[str, str]:
        """Get the time range of the dataset."""
        timestamp_columns = [
            col for col in self.column_metadata.keys() if "timestamp" in col.lower()
        ]

        if not timestamp_columns:
            return {"earliest": "Unknown", "latest": "Unknown"}

        timestamp_col = timestamp_columns[0]
        escaped_timestamp_col = f'`{timestamp_col}`' if not timestamp_col.startswith('`') else timestamp_col
        try:
            query = f"""
            SELECT
                min({escaped_timestamp_col}) as earliest,
                max({escaped_timestamp_col}) as latest
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE {escaped_timestamp_col} IS NOT NULL
            """
            result = self.clickhouse.execute_query(query)
            if result:
                return {
                    "earliest": str(result[0]["earliest"]),
                    "latest": str(result[0]["latest"]),
                }
        except Exception as e:
            print(f"Failed to get time range: {e}")

        return {"earliest": "Unknown", "latest": "Unknown"}

    def analyze_column_group(
        self,
        columns: List[str],
        time_filter: Optional[Dict[str, str]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Analyze a group of columns together for drill-down analysis."""
        if not columns:
            return {}

        # Build time filter condition
        time_condition = ""
        if time_filter and "start" in time_filter and "end" in time_filter:
            timestamp_col = next(
                (col for col in columns if "timestamp" in col.lower()), None
            )
            if timestamp_col:
                escaped_timestamp_col = f'`{timestamp_col}`' if not timestamp_col.startswith('`') else timestamp_col
                time_condition = f"AND {escaped_timestamp_col} BETWEEN '{time_filter['start']}' AND '{time_filter['end']}'"

        # Get group statistics with escaped column names
        escaped_columns = [f'`{col}`' if not col.startswith('`') else col for col in columns]
        column_list = ", ".join(escaped_columns)
        group_query = f"""
        SELECT
            {column_list},
            count() as frequency,
            count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE 1=1 {time_condition}) as percentage
        FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
        WHERE {" AND ".join(f"{escaped_col} IS NOT NULL AND {escaped_col} != ''" for escaped_col in escaped_columns)} {time_condition}
        GROUP BY {column_list}
        ORDER BY frequency DESC
        LIMIT {limit}
        """

        try:
            result = self.clickhouse.execute_query(group_query)
            return {
                "groups": result,
                "total_groups": len(result),
                "columns": columns,
                "time_filter": time_filter,
            }
        except Exception as e:
            print(f"Failed to analyze column group: {e}")
            return {"error": str(e)}
