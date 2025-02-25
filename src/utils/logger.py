import sys
from pathlib import Path
from loguru import logger
from datetime import datetime

class LoggerSetup:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Generate log filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"security_scan_{timestamp}.log"
        
        self.setup_logger()

    def setup_logger(self):
        # Remove any existing handlers
        logger.remove()

        # Add console handler with color
        logger.add(
            sys.stdout,
            colorize=True,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                   "<level>{level: <8}</level> | "
                   "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                   "<level>{message}</level>",
            level="INFO"
        )

        # Add file handler
        logger.add(
            self.log_file,
            rotation="500 MB",  # Rotate when file reaches 500MB
            retention="1 week",  # Keep logs for 1 week
            compression="zip",   # Compress rotated logs
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | "
                   "{name}:{function}:{line} - {message}",
            level="DEBUG"
        )

    def get_logger(self):
        return logger

class SecurityAuditLogger:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.logger = logger.bind(scan_id=scan_id)

    def tool_start(self, tool_name: str, parameters: dict):
        self.logger.info(f"Starting {tool_name} scan with parameters: {parameters}")

    def tool_complete(self, tool_name: str, result: dict):
        self.logger.info(f"Completed {tool_name} scan successfully")
        self.logger.debug(f"Scan results: {result}")

    def tool_error(self, tool_name: str, error: Exception):
        self.logger.error(f"Error in {tool_name} scan: {str(error)}")
        self.logger.exception(error)

    def scope_violation(self, target: str):
        self.logger.warning(f"Attempted scan on out-of-scope target: {target}")

    def task_update(self, task_id: str, status: str):
        self.logger.info(f"Task {task_id} status updated to: {status}")

    def vulnerability_found(self, details: dict):
        self.logger.warning(f"Potential vulnerability discovered: {details}")

    def scan_summary(self, summary: dict):
        self.logger.info(f"Scan summary: {summary}")

def get_audit_logger(scan_id: str) -> SecurityAuditLogger:
    """Factory function to create a new SecurityAuditLogger instance"""
    return SecurityAuditLogger(scan_id)