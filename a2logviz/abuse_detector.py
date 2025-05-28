"""Advanced abuse detection and anomaly analysis for Apache logs."""

from dataclasses import dataclass

import pandas as pd


@dataclass
class AbusePattern:
    """Represents a detected abuse pattern."""

    pattern_type: str
    severity: str
    description: str
    affected_ips: list[str]
    request_count: int
    confidence: float
    details: dict[str, any]


class AbuseDetector:
    """Advanced abuse detection system for web server logs."""

    def __init__(self, df: pd.DataFrame) -> None:
        """Initialize the abuse detector.

        Args:
            df: DataFrame containing parsed log data
        """
        self.df = df.copy()
        self._prepare_data()

    def _prepare_data(self) -> None:
        """Prepare data for analysis."""
        # Ensure we have the required columns
        if "timestamp" in self.df.columns:
            self.df["hour"] = pd.to_datetime(self.df["timestamp"]).dt.hour
            self.df["date"] = pd.to_datetime(self.df["timestamp"]).dt.date

        # Extract file extensions from paths
        if "path" in self.df.columns:
            self.df["file_extension"] = (
                self.df["path"]
                .str.extract(r"\.([a-zA-Z0-9]+)$")[0]
                .fillna("no_extension")
            )

    def detect_brute_force_attacks(
        self,
        min_attempts: int = 50,
        time_window_hours: int = 1,
        error_threshold: float = 0.8,
    ) -> list[AbusePattern]:
        """Detect potential brute force attacks.

        Args:
            min_attempts: Minimum number of requests to consider
            time_window_hours: Time window for grouping requests
            error_threshold: Minimum ratio of error responses

        Returns:
            List of detected brute force patterns
        """
        patterns = []

        # Group by IP and hour to find concentrated failed attempts
        ip_hour_groups = (
            self.df.groupby(["remote_host", "hour"])
            .agg(
                {
                    "status_code": ["count", lambda x: (x >= 400).sum()],
                    "path": "nunique",
                }
            )
            .round(2)
        )

        ip_hour_groups.columns = ["total_requests", "error_requests", "unique_paths"]
        ip_hour_groups = ip_hour_groups.reset_index()

        # Calculate error rate
        ip_hour_groups["error_rate"] = (
            ip_hour_groups["error_requests"] / ip_hour_groups["total_requests"]
        )

        # Find suspicious patterns
        suspicious = ip_hour_groups[
            (ip_hour_groups["total_requests"] >= min_attempts)
            & (ip_hour_groups["error_rate"] >= error_threshold)
        ]

        for _, row in suspicious.iterrows():
            confidence = min(
                1.0,
                (row["error_rate"] - error_threshold) * 2
                + (row["total_requests"] / min_attempts) * 0.3,
            )

            patterns.append(
                AbusePattern(
                    pattern_type="brute_force",
                    severity="high" if confidence > 0.8 else "medium",
                    description=f"High error rate ({row['error_rate']:.1%}) with {row['total_requests']} requests",
                    affected_ips=[row["remote_host"]],
                    request_count=int(row["total_requests"]),
                    confidence=confidence,
                    details={
                        "error_rate": row["error_rate"],
                        "hour": row["hour"],
                        "unique_paths": row["unique_paths"],
                    },
                )
            )

        return patterns

    def detect_ddos_patterns(
        self, request_threshold: int = 1000, unique_path_threshold: int = 5
    ) -> list[AbusePattern]:
        """Detect potential DDoS patterns.

        Args:
            request_threshold: Minimum requests per IP to consider
            unique_path_threshold: Maximum unique paths for DDoS pattern

        Returns:
            List of detected DDoS patterns
        """
        patterns = []

        # Analyze request patterns by IP
        ip_stats = (
            self.df.groupby("remote_host")
            .agg(
                {
                    "path": ["count", "nunique"],
                    "status_code": lambda x: (x == 200).sum(),
                    "user_agent": "nunique",
                }
            )
            .round(2)
        )

        ip_stats.columns = [
            "total_requests",
            "unique_paths",
            "success_requests",
            "unique_agents",
        ]
        ip_stats = ip_stats.reset_index()

        # Calculate success rate and path diversity
        ip_stats["success_rate"] = (
            ip_stats["success_requests"] / ip_stats["total_requests"]
        )
        ip_stats["path_diversity"] = (
            ip_stats["unique_paths"] / ip_stats["total_requests"]
        )

        # Find DDoS patterns: high volume, low path diversity
        ddos_candidates = ip_stats[
            (ip_stats["total_requests"] >= request_threshold)
            & (ip_stats["unique_paths"] <= unique_path_threshold)
        ]

        for _, row in ddos_candidates.iterrows():
            confidence = min(
                1.0,
                (row["total_requests"] / request_threshold) * 0.5
                + (1 - row["path_diversity"]) * 0.5,
            )

            patterns.append(
                AbusePattern(
                    pattern_type="ddos",
                    severity=(
                        "critical"
                        if row["total_requests"] > request_threshold * 5
                        else "high"
                    ),
                    description=f"High volume ({row['total_requests']} requests) targeting few paths",
                    affected_ips=[row["remote_host"]],
                    request_count=int(row["total_requests"]),
                    confidence=confidence,
                    details={
                        "unique_paths": row["unique_paths"],
                        "success_rate": row["success_rate"],
                        "path_diversity": row["path_diversity"],
                        "unique_agents": row["unique_agents"],
                    },
                )
            )

        return patterns

    def detect_scanning_behavior(
        self, min_404_requests: int = 20, path_diversity_threshold: float = 0.8
    ) -> list[AbusePattern]:
        """Detect directory/vulnerability scanning behavior.

        Args:
            min_404_requests: Minimum 404 requests to consider scanning
            path_diversity_threshold: Minimum path diversity ratio

        Returns:
            List of detected scanning patterns
        """
        patterns = []

        # Focus on 404 requests for scanning detection
        not_found_requests = self.df[self.df["status_code"] == 404]

        if not_found_requests.empty:
            return patterns

        # Analyze 404 patterns by IP
        scanning_stats = not_found_requests.groupby("remote_host").agg(
            {"path": ["count", "nunique"], "user_agent": "nunique"}
        )

        scanning_stats.columns = [
            "not_found_requests",
            "unique_404_paths",
            "unique_agents",
        ]
        scanning_stats = scanning_stats.reset_index()

        # Calculate path diversity for 404s
        scanning_stats["path_diversity_404"] = (
            scanning_stats["unique_404_paths"] / scanning_stats["not_found_requests"]
        )

        # Find scanning patterns
        scanners = scanning_stats[
            (scanning_stats["not_found_requests"] >= min_404_requests)
            & (scanning_stats["path_diversity_404"] >= path_diversity_threshold)
        ]

        for _, row in scanners.iterrows():
            confidence = min(
                1.0,
                (row["path_diversity_404"] - path_diversity_threshold) * 2
                + (row["not_found_requests"] / min_404_requests) * 0.3,
            )

            patterns.append(
                AbusePattern(
                    pattern_type="scanning",
                    severity="medium",
                    description=f"High path diversity in 404s ({row['unique_404_paths']} unique paths)",
                    affected_ips=[row["remote_host"]],
                    request_count=int(row["not_found_requests"]),
                    confidence=confidence,
                    details={
                        "unique_404_paths": row["unique_404_paths"],
                        "path_diversity_404": row["path_diversity_404"],
                        "unique_agents": row["unique_agents"],
                    },
                )
            )

        return patterns

    def detect_bot_behavior(self) -> list[AbusePattern]:
        """Detect automated bot behavior based on user agents and patterns."""
        patterns = []

        # Known bot indicators in user agents
        bot_indicators = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "python",
            "curl",
            "wget",
            "automation",
            "headless",
            "phantom",
            "selenium",
        ]

        # Analyze user agent patterns
        if "user_agent" not in self.df.columns:
            return patterns

        ua_stats = self.df.groupby("user_agent").agg(
            {
                "remote_host": ["count", "nunique"],
                "path": "nunique",
                "status_code": lambda x: (x == 200).sum(),
            }
        )

        ua_stats.columns = [
            "total_requests",
            "unique_ips",
            "unique_paths",
            "success_requests",
        ]
        ua_stats = ua_stats.reset_index()

        # Find suspicious user agents
        for _, row in ua_stats.iterrows():
            user_agent = str(row["user_agent"]).lower()

            # Check for bot indicators
            is_likely_bot = any(indicator in user_agent for indicator in bot_indicators)

            # High request volume with single IP suggests automation
            high_volume_single_ip = (
                row["total_requests"] > 100 and row["unique_ips"] == 1
            )

            if is_likely_bot or high_volume_single_ip:
                confidence = 0.9 if is_likely_bot else 0.6

                patterns.append(
                    AbusePattern(
                        pattern_type="bot_behavior",
                        severity="low" if is_likely_bot else "medium",
                        description=f"Bot-like user agent with {row['total_requests']} requests",
                        affected_ips=[],  # We'd need to join back to get IPs
                        request_count=int(row["total_requests"]),
                        confidence=confidence,
                        details={
                            "user_agent": row["user_agent"],
                            "unique_ips": row["unique_ips"],
                            "unique_paths": row["unique_paths"],
                            "is_explicit_bot": is_likely_bot,
                        },
                    )
                )

        return patterns[:10]  # Limit to top 10 bot patterns

    def analyze_all_patterns(self) -> dict[str, list[AbusePattern]]:
        """Run all abuse detection methods and return categorized results."""
        results = {
            "brute_force": self.detect_brute_force_attacks(),
            "ddos": self.detect_ddos_patterns(),
            "scanning": self.detect_scanning_behavior(),
            "bot_behavior": self.detect_bot_behavior(),
        }

        return results

    def get_top_threats(self, limit: int = 10) -> list[AbusePattern]:
        """Get the top threats across all categories ordered by severity and confidence."""
        all_patterns = []
        for patterns in self.analyze_all_patterns().values():
            all_patterns.extend(patterns)

        # Sort by severity and confidence
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        sorted_patterns = sorted(
            all_patterns,
            key=lambda p: (severity_order.get(p.severity, 0), p.confidence),
            reverse=True,
        )

        return sorted_patterns[:limit]
