"""Apache log parser with configurable format strings."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import apachelogs
import pandas as pd


@dataclass
class LogEntry:
    """Represents a parsed Apache log entry."""

    remote_host: str
    remote_logname: Optional[str]
    remote_user: Optional[str]
    timestamp: datetime
    request_line: str
    status_code: int
    response_size: Optional[int]
    referer: Optional[str]
    user_agent: Optional[str]
    request_time: Optional[float]


class ApacheLogParser:
    """Parser for Apache log files with configurable format strings."""

    # Common Apache log format patterns (regex)
    COMMON_REGEX_FORMATS = {
        "common": r'(?P<remote_host>\S+) (?P<remote_logname>\S+) (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<request_line>[^"]*)" (?P<status_code>\d+) (?P<response_size>\S+)',
        "combined": r'(?P<remote_host>\S+) (?P<remote_logname>\S+) (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<request_line>[^"]*)" (?P<status_code>\d+) (?P<response_size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
        "combined_with_time": r'(?P<remote_host>\S+) (?P<remote_logname>\S+) (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<request_line>[^"]*)" (?P<status_code>\d+) (?P<response_size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<request_time>\d+)',
    }

    # Common Apache LogFormat patterns
    COMMON_LOGFORMAT_PATTERNS = {
        "common": '%h %l %u %t "%r" %>s %O',
        "combined": '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"',
        "combined_with_time": '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i" %D',
        "vhost_combined": '%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"',
    }

    def __init__(self, log_format: str = "combined") -> None:
        """Initialize parser with a log format.

        Args:
            log_format: Either a predefined format name, Apache LogFormat string, or custom regex pattern
        """
        self.log_format = log_format
        self.use_apachelogs = False
        self.pattern: Optional[re.Pattern] = None
        self.apache_parser: Optional[apachelogs.LogParser] = None

        # Try to determine format type and set up appropriate parser
        self._setup_parser()

    def _setup_parser(self) -> None:
        """Set up the appropriate parser based on the log format."""
        # Check if it's a predefined format name
        if self.log_format in self.COMMON_LOGFORMAT_PATTERNS:
            # Use Apache LogFormat
            self.use_apachelogs = True
            self.apache_parser = apachelogs.LogParser(
                self.COMMON_LOGFORMAT_PATTERNS[self.log_format]
            )
        elif self.log_format in self.COMMON_REGEX_FORMATS:
            # Use regex format
            self.use_apachelogs = False
            self.pattern = re.compile(self.COMMON_REGEX_FORMATS[self.log_format])
        elif self._is_logformat_string(self.log_format):
            # Custom Apache LogFormat string
            self.use_apachelogs = True
            try:
                self.apache_parser = apachelogs.LogParser(self.log_format)
            except Exception as e:
                print(f"Failed to parse LogFormat string '{self.log_format}': {e}")
                # Fallback to regex if LogFormat parsing fails
                self.use_apachelogs = False
                try:
                    self.pattern = re.compile(self.log_format)
                except re.error:
                    raise ValueError(f"Invalid format string: {self.log_format}")
        else:
            # Assume custom regex pattern
            self.use_apachelogs = False
            try:
                self.pattern = re.compile(self.log_format)
            except re.error:
                raise ValueError(f"Invalid regex pattern: {self.log_format}")

    def _is_logformat_string(self, format_str: str) -> bool:
        """Check if the format string looks like an Apache LogFormat string."""
        # Apache LogFormat strings typically contain % directives
        return "%" in format_str and any(
            directive in format_str
            for directive in [
                "%h",
                "%l",
                "%u",
                "%t",
                "%r",
                "%s",
                "%O",
                "%i",
                "%v",
                "%p",
                "%D",
                "%T",
            ]
        )

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Apache timestamp format."""
        # Apache default format: [25/Dec/1995:10:00:00 +0000]
        try:
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            # Try without timezone
            return datetime.strptime(timestamp_str[:20], "%d/%b/%Y:%H:%M:%S")

    def _safe_convert(
        self, value: str, converter: type, default: Optional[object] = None
    ) -> object:
        """Safely convert a string value to the specified type."""
        if value == "-" or value is None:
            return default
        try:
            return converter(value)
        except (ValueError, TypeError):
            return default

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into a LogEntry.

        Args:
            line: A single line from an Apache log file

        Returns:
            LogEntry if parsing succeeds, None otherwise
        """
        if self.use_apachelogs:
            return self._parse_line_apachelogs(line)
        else:
            return self._parse_line_regex(line)

    def _parse_line_apachelogs(self, line: str) -> Optional[LogEntry]:
        """Parse a line using the apachelogs library."""
        try:
            if not self.apache_parser:
                return None

            entry = self.apache_parser.parse(line.strip())

            # Extract request time if available (microseconds to seconds)
            request_time = None
            if hasattr(entry, "request_time_us") and entry.request_time_us is not None:
                request_time = entry.request_time_us / 1_000_000.0
            elif hasattr(entry, "request_time") and entry.request_time is not None:
                request_time = float(entry.request_time)

            return LogEntry(
                remote_host=entry.remote_host or "",
                remote_logname=(
                    entry.remote_logname if entry.remote_logname != "-" else None
                ),
                remote_user=entry.remote_user if entry.remote_user != "-" else None,
                timestamp=entry.request_time_fields.timestamp,
                request_line=entry.request_line or "",
                status_code=entry.final_status or 0,
                response_size=entry.bytes_sent if entry.bytes_sent != "-" else None,
                referer=(
                    entry.headers_in.get("Referer")
                    if hasattr(entry, "headers_in") and entry.headers_in
                    else None
                ),
                user_agent=(
                    entry.headers_in.get("User-Agent")
                    if hasattr(entry, "headers_in") and entry.headers_in
                    else None
                ),
                request_time=request_time,
            )
        except Exception:
            # Fallback for parsing errors
            return None

    def _parse_line_regex(self, line: str) -> Optional[LogEntry]:
        """Parse a line using regex patterns."""
        if not self.pattern:
            return None

        match = self.pattern.match(line.strip())
        if not match:
            return None

        groups = match.groupdict()

        try:
            return LogEntry(
                remote_host=groups.get("remote_host", ""),
                remote_logname=self._safe_convert(groups.get("remote_logname"), str),
                remote_user=self._safe_convert(groups.get("remote_user"), str),
                timestamp=self._parse_timestamp(groups.get("timestamp", "")),
                request_line=groups.get("request_line", ""),
                status_code=int(groups.get("status_code", 0)),
                response_size=self._safe_convert(groups.get("response_size"), int),
                referer=self._safe_convert(groups.get("referer"), str),
                user_agent=self._safe_convert(groups.get("user_agent"), str),
                request_time=self._safe_convert(groups.get("request_time"), float),
            )
        except (ValueError, KeyError) as e:
            print(f"Failed to parse line: {line[:100]}... Error: {e}")
            return None

    def parse_file(self, filepath: Union[str, Path]) -> Iterator[LogEntry]:
        """Parse an entire log file.

        Args:
            filepath: Path to the Apache log file

        Yields:
            LogEntry objects for each successfully parsed line
        """
        filepath = Path(filepath)
        with filepath.open("r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                entry = self.parse_line(line)
                if entry:
                    yield entry
                elif line.strip():  # Only warn for non-empty lines
                    if line_num <= 10:  # Only show first 10 parsing errors
                        print(f"Warning: Failed to parse line {line_num}")

    def parse_files_to_dataframe(
        self, filepaths: list[Union[str, Path]]
    ) -> pd.DataFrame:
        """Parse multiple log files into a pandas DataFrame.

        Args:
            filepaths: List of paths to Apache log files

        Returns:
            DataFrame with parsed log entries
        """
        entries = []
        for filepath in filepaths:
            print(f"Parsing {filepath}...")
            entries.extend(self.parse_file(filepath))

        if not entries:
            return pd.DataFrame()

        # Convert to DataFrame
        data = []
        for entry in entries:
            data.append(
                {
                    "remote_host": entry.remote_host,
                    "remote_logname": entry.remote_logname,
                    "remote_user": entry.remote_user,
                    "timestamp": entry.timestamp,
                    "request_line": entry.request_line,
                    "status_code": entry.status_code,
                    "response_size": entry.response_size,
                    "referer": entry.referer,
                    "user_agent": entry.user_agent,
                    "request_time": entry.request_time,
                }
            )

        df = pd.DataFrame(data)

        # Extract additional fields from request_line
        if "request_line" in df.columns:
            request_parts = df["request_line"].str.split(" ", n=2, expand=True)
            df["method"] = request_parts[0] if len(request_parts.columns) > 0 else ""
            df["path"] = request_parts[1] if len(request_parts.columns) > 1 else ""
            df["protocol"] = request_parts[2] if len(request_parts.columns) > 2 else ""

        return df
