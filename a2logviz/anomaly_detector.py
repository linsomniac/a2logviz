"""Advanced anomaly detection system for log data analysis."""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .clickhouse_client import ClickHouseLocalClient


@dataclass
class AnomalyAlert:
    """Represents an anomaly detected in the data."""

    alert_type: str  # spike, outlier, pattern_break, threshold_breach
    severity: str  # critical, high, medium, low
    column: str
    description: str
    value: Any
    frequency: int
    percentage: float
    baseline: Optional[float] = None
    deviation: Optional[float] = None
    time_window: Optional[str] = None
    recommendations: List[str] = None


class AdvancedAnomalyDetector:
    """Advanced anomaly detection for security and operational monitoring."""

    def __init__(self, clickhouse_client: ClickHouseLocalClient):
        """Initialize the anomaly detector.

        Args:
            clickhouse_client: ClickHouse client with loaded log data
        """
        self.clickhouse = clickhouse_client

    def detect_all_anomalies(
        self, time_filter: Optional[Dict[str, str]] = None
    ) -> List[AnomalyAlert]:
        """Run comprehensive anomaly detection across all relevant columns."""
        alerts = []

        # Get time condition
        time_condition = self._build_time_condition(time_filter)

        # IP-based anomalies
        alerts.extend(self._detect_ip_anomalies(time_condition))

        # Status code anomalies
        alerts.extend(self._detect_status_anomalies(time_condition))

        # User agent anomalies
        alerts.extend(self._detect_user_agent_anomalies(time_condition))

        # Request pattern anomalies
        alerts.extend(self._detect_request_pattern_anomalies(time_condition))

        # Temporal anomalies
        alerts.extend(self._detect_temporal_anomalies(time_condition))

        # Response size anomalies
        alerts.extend(self._detect_response_size_anomalies(time_condition))

        # Sort by severity and frequency
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        alerts.sort(
            key=lambda x: (severity_order.get(x.severity, 0), x.frequency), reverse=True
        )

        return alerts

    def _build_time_condition(self, time_filter: Optional[Dict[str, str]]) -> str:
        """Build time filtering condition for SQL queries."""
        if (
            not time_filter
            or not time_filter.get("start")
            or not time_filter.get("end")
        ):
            return ""

        return (
            f"AND timestamp BETWEEN '{time_filter['start']}' AND '{time_filter['end']}'"
        )

    def _detect_ip_anomalies(self, time_condition: str) -> List[AnomalyAlert]:
        """Detect IP-based anomalies."""
        alerts = []

        try:
            # High-frequency IP addresses
            query = f"""
            SELECT
                remote_host as ip,
                count() as request_count,
                count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE 1=1 {time_condition}) as percentage,
                countIf(status_code >= 400) as error_count,
                countIf(status_code = 404) as not_found_count,
                uniq(path) as unique_paths,
                uniq(user_agent) as unique_agents
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE remote_host IS NOT NULL AND remote_host != '' {time_condition}
            GROUP BY remote_host
            HAVING request_count > 1000 OR percentage > 5
            ORDER BY request_count DESC
            LIMIT 20
            """

            results = self.clickhouse.execute_query(query)
            for row in results:
                request_count = int(row["request_count"])
                percentage = float(row["percentage"])
                error_rate = (
                    int(row["error_count"]) / request_count if request_count > 0 else 0
                )
                path_diversity = (
                    int(row["unique_paths"]) / request_count if request_count > 0 else 0
                )

                # Determine severity
                severity = "low"
                recommendations = []

                if request_count > 10000:
                    severity = "critical"
                    recommendations.append("Investigate potential DDoS attack")
                elif request_count > 5000:
                    severity = "high"
                    recommendations.append("Monitor for sustained high activity")
                elif percentage > 10:
                    severity = "medium"
                    recommendations.append("Review traffic patterns from this IP")

                if error_rate > 0.5:
                    severity = "high"
                    recommendations.append(
                        "High error rate suggests scanning/brute force"
                    )

                if path_diversity < 0.1 and request_count > 1000:
                    recommendations.append(
                        "Low path diversity indicates focused attack"
                    )

                alerts.append(
                    AnomalyAlert(
                        alert_type="spike",
                        severity=severity,
                        column="remote_host",
                        description=f"IP {row['ip']} generated {request_count:,} requests ({percentage:.1f}% of total)",
                        value=row["ip"],
                        frequency=request_count,
                        percentage=percentage,
                        recommendations=recommendations,
                    )
                )

        except Exception as e:
            print(f"Error detecting IP anomalies: {e}")

        return alerts

    def _detect_status_anomalies(self, time_condition: str) -> List[AnomalyAlert]:
        """Detect status code anomalies."""
        alerts = []

        try:
            # Unusual status code distributions
            query = f"""
            SELECT
                status_code,
                count() as frequency,
                count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE 1=1 {time_condition}) as percentage
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE status_code IS NOT NULL {time_condition}
            GROUP BY status_code
            ORDER BY frequency DESC
            """

            results = self.clickhouse.execute_query(query)
            total_requests = sum(int(row["frequency"]) for row in results)

            for row in results:
                status_code = int(row["status_code"])
                frequency = int(row["frequency"])
                percentage = float(row["percentage"])

                # Flag unusual patterns
                recommendations = []
                severity = "low"

                if status_code >= 500 and percentage > 5:
                    severity = "critical"
                    recommendations.append(
                        "High server error rate - investigate backend issues"
                    )
                elif status_code == 404 and percentage > 20:
                    severity = "high"
                    recommendations.append("High 404 rate suggests scanning activity")
                elif status_code in [401, 403] and percentage > 10:
                    severity = "medium"
                    recommendations.append("High authentication failure rate")
                elif status_code in [429, 503] and percentage > 1:
                    severity = "medium"
                    recommendations.append(
                        "Rate limiting or service unavailability detected"
                    )

                if recommendations:
                    alerts.append(
                        AnomalyAlert(
                            alert_type="threshold_breach",
                            severity=severity,
                            column="status_code",
                            description=f"Status code {status_code} appears in {percentage:.1f}% of requests",
                            value=status_code,
                            frequency=frequency,
                            percentage=percentage,
                            recommendations=recommendations,
                        )
                    )

        except Exception as e:
            print(f"Error detecting status anomalies: {e}")

        return alerts

    def _detect_user_agent_anomalies(self, time_condition: str) -> List[AnomalyAlert]:
        """Detect user agent anomalies."""
        alerts = []

        try:
            # Suspicious user agents
            query = f"""
            SELECT
                user_agent,
                count() as frequency,
                count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE user_agent IS NOT NULL {time_condition}) as percentage,
                uniq(remote_host) as unique_ips
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE user_agent IS NOT NULL AND user_agent != '' {time_condition}
            GROUP BY user_agent
            HAVING frequency > 100
            ORDER BY frequency DESC
            LIMIT 50
            """

            results = self.clickhouse.execute_query(query)

            for row in results:
                user_agent = row["user_agent"]
                frequency = int(row["frequency"])
                percentage = float(row["percentage"])
                unique_ips = int(row["unique_ips"])

                recommendations = []
                severity = "low"

                # Check for bot indicators
                bot_indicators = [
                    "bot",
                    "crawler",
                    "spider",
                    "scraper",
                    "python",
                    "curl",
                    "wget",
                    "scan",
                    "test",
                    "exploit",
                    "attack",
                ]

                user_agent_lower = user_agent.lower()
                is_suspicious_bot = any(
                    indicator in user_agent_lower for indicator in bot_indicators
                )

                # Check for automation patterns
                if unique_ips == 1 and frequency > 1000:
                    severity = "medium"
                    recommendations.append(
                        "Single IP with high frequency suggests automation"
                    )

                if is_suspicious_bot and frequency > 500:
                    severity = "medium"
                    recommendations.append("Potential malicious bot activity detected")

                # Check for unusual user agent patterns
                if len(user_agent) < 10 or user_agent.count(" ") < 2:
                    severity = "medium"
                    recommendations.append(
                        "Unusually short or simple user agent string"
                    )

                if percentage > 10 and not any(
                    browser in user_agent_lower
                    for browser in ["mozilla", "chrome", "safari", "firefox"]
                ):
                    severity = "high"
                    recommendations.append("High frequency non-browser user agent")

                if recommendations:
                    alerts.append(
                        AnomalyAlert(
                            alert_type="pattern_break",
                            severity=severity,
                            column="user_agent",
                            description=f"Suspicious user agent with {frequency:,} requests ({percentage:.1f}%)",
                            value=(
                                user_agent[:100] + "..."
                                if len(user_agent) > 100
                                else user_agent
                            ),
                            frequency=frequency,
                            percentage=percentage,
                            recommendations=recommendations,
                        )
                    )

        except Exception as e:
            print(f"Error detecting user agent anomalies: {e}")

        return alerts

    def _detect_request_pattern_anomalies(
        self, time_condition: str
    ) -> List[AnomalyAlert]:
        """Detect request pattern anomalies."""
        alerts = []

        try:
            # Unusual request paths
            query = f"""
            SELECT
                path,
                count() as frequency,
                count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE path IS NOT NULL {time_condition}) as percentage,
                uniq(remote_host) as unique_ips,
                countIf(status_code = 404) as not_found_count
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE path IS NOT NULL AND path != '' {time_condition}
            GROUP BY path
            HAVING frequency > 50
            ORDER BY frequency DESC
            LIMIT 100
            """

            results = self.clickhouse.execute_query(query)

            for row in results:
                path = row["path"]
                frequency = int(row["frequency"])
                percentage = float(row["percentage"])
                unique_ips = int(row["unique_ips"])
                not_found_count = int(row["not_found_count"])

                recommendations = []
                severity = "low"

                # Check for suspicious paths
                suspicious_patterns = [
                    "admin",
                    "login",
                    "wp-",
                    "phpmyadmin",
                    "sql",
                    "config",
                    "backup",
                    "test",
                    "dev",
                    "debug",
                    ".env",
                    "api/",
                    "shell",
                ]

                path_lower = path.lower()
                is_suspicious_path = any(
                    pattern in path_lower for pattern in suspicious_patterns
                )

                # High 404 rate on specific path
                if not_found_count / frequency > 0.8 and frequency > 100:
                    severity = "medium"
                    recommendations.append(
                        "High 404 rate suggests scanning for vulnerabilities"
                    )

                # Suspicious path with high frequency
                if is_suspicious_path and frequency > 200:
                    severity = "high"
                    recommendations.append("Potential attack on sensitive endpoint")

                # Low IP diversity suggests focused attack
                if unique_ips < 3 and frequency > 500:
                    severity = "medium"
                    recommendations.append(
                        "Few IPs accessing path frequently - potential attack"
                    )

                if percentage > 5 and (
                    is_suspicious_path or not_found_count / frequency > 0.5
                ):
                    severity = "high"
                    recommendations.append(
                        "High percentage of suspicious path requests"
                    )

                if recommendations:
                    alerts.append(
                        AnomalyAlert(
                            alert_type="pattern_break",
                            severity=severity,
                            column="path",
                            description=f"Suspicious path '{path}' accessed {frequency:,} times ({percentage:.1f}%)",
                            value=path,
                            frequency=frequency,
                            percentage=percentage,
                            recommendations=recommendations,
                        )
                    )

        except Exception as e:
            print(f"Error detecting request pattern anomalies: {e}")

        return alerts

    def _detect_temporal_anomalies(self, time_condition: str) -> List[AnomalyAlert]:
        """Detect temporal anomalies."""
        alerts = []

        try:
            # Request spikes by hour
            query = f"""
            SELECT
                toHour(timestamp) as hour,
                count() as frequency,
                avg(count()) OVER () as avg_frequency
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE timestamp IS NOT NULL {time_condition}
            GROUP BY hour
            ORDER BY hour
            """

            results = self.clickhouse.execute_query(query)

            if results:
                avg_frequency = float(results[0]["avg_frequency"])

                for row in results:
                    hour = int(row["hour"])
                    frequency = int(row["frequency"])
                    deviation = (
                        (frequency - avg_frequency) / avg_frequency
                        if avg_frequency > 0
                        else 0
                    )

                    if deviation > 2.0:  # More than 3x average
                        severity = "high" if deviation > 5.0 else "medium"
                        recommendations = [
                            "Investigate traffic spike during this hour",
                            "Check for coordinated attacks or unusual events",
                        ]

                        alerts.append(
                            AnomalyAlert(
                                alert_type="spike",
                                severity=severity,
                                column="timestamp",
                                description=f"Traffic spike at hour {hour}:00 - {frequency:,} requests ({deviation*100:.0f}% above average)",
                                value=f"{hour}:00",
                                frequency=frequency,
                                percentage=(
                                    frequency
                                    / sum(int(r["frequency"]) for r in results)
                                )
                                * 100,
                                baseline=avg_frequency,
                                deviation=deviation,
                                recommendations=recommendations,
                            )
                        )

        except Exception as e:
            print(f"Error detecting temporal anomalies: {e}")

        return alerts

    def _detect_response_size_anomalies(
        self, time_condition: str
    ) -> List[AnomalyAlert]:
        """Detect response size anomalies."""
        alerts = []

        try:
            # Unusual response sizes
            query = f"""
            SELECT
                response_size,
                count() as frequency,
                count() * 100.0 / (SELECT count() FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}') WHERE response_size IS NOT NULL {time_condition}) as percentage
            FROM file('{self.clickhouse.data_file}', CSV, '{self.clickhouse.csv_schema}')
            WHERE response_size IS NOT NULL AND response_size > 0 {time_condition}
            GROUP BY response_size
            HAVING frequency > 100
            ORDER BY response_size DESC
            LIMIT 20
            """

            results = self.clickhouse.execute_query(query)

            for row in results:
                response_size = int(row["response_size"])
                frequency = int(row["frequency"])
                percentage = float(row["percentage"])

                recommendations = []
                severity = "low"

                # Very large responses might indicate data exfiltration
                if response_size > 10_000_000 and frequency > 10:  # > 10MB
                    severity = "high"
                    recommendations.append(
                        "Large response sizes may indicate data exfiltration"
                    )

                # Very small responses with high frequency might indicate errors
                elif response_size < 100 and percentage > 20:
                    severity = "medium"
                    recommendations.append(
                        "Many small responses may indicate errors or blocked requests"
                    )

                if recommendations:
                    alerts.append(
                        AnomalyAlert(
                            alert_type="outlier",
                            severity=severity,
                            column="response_size",
                            description=f"Unusual response size {response_size:,} bytes in {frequency:,} requests ({percentage:.1f}%)",
                            value=response_size,
                            frequency=frequency,
                            percentage=percentage,
                            recommendations=recommendations,
                        )
                    )

        except Exception as e:
            print(f"Error detecting response size anomalies: {e}")

        return alerts

    def get_security_summary(
        self, time_filter: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Get a comprehensive security summary."""
        alerts = self.detect_all_anomalies(time_filter)

        # Categorize alerts
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        high_alerts = [a for a in alerts if a.severity == "high"]
        medium_alerts = [a for a in alerts if a.severity == "medium"]

        # Count by type
        alert_types = {}
        for alert in alerts:
            alert_types[alert.alert_type] = alert_types.get(alert.alert_type, 0) + 1

        return {
            "total_alerts": len(alerts),
            "critical_count": len(critical_alerts),
            "high_count": len(high_alerts),
            "medium_count": len(medium_alerts),
            "alert_types": alert_types,
            "top_alerts": alerts[:10],
            "recommendations": list(
                set(
                    rec
                    for alert in alerts[:20]
                    for rec in (alert.recommendations or [])
                )
            )[:10],
        }
