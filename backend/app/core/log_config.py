import json
import logging
import logging.handlers
import os
import sys
import threading
import time
from datetime import datetime
from logging.config import dictConfig

import redis

from app.core.config import settings

# Log directory
# Fix path calculation to always point to project root
script_path = os.path.abspath(__file__)
# Use project structure information to locate project root from current file
# Current file is at app/core/log_config.py, go up two levels (not three) to reach project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(script_path), "../.."))

# Remove debug output to avoid repeated printing in multi-process environment
# print(f"Log directory BASE_DIR: {BASE_DIR}")

LOG_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, f"app_{datetime.now().strftime('%Y%m%d')}.log")
SQLALCHEMY_LOG_FILE = os.path.join(
    LOG_DIR, f"sqlalchemy_{datetime.now().strftime('%Y%m%d')}.log"
)
MASTER_PROCESS_FILE = os.path.join(LOG_DIR, "master_process.lock")

# Set log level based on environment
ENV = settings.ENV.lower()
LOG_LEVELS = {"development": "DEBUG", "testing": "INFO", "production": "WARNING"}
LOG_LEVEL = LOG_LEVELS.get(ENV, "INFO")
SQLALCHEMY_LEVEL = "INFO" if ENV == "production" else "DEBUG"


# Determine if this is the master process
def is_master_process():
    # Get current process ID
    pid = os.getpid()

    # Check if UVICORN_PROCESS_ID environment variable exists
    worker_id = os.environ.get(
        "UVICORN_WORKER_ID", os.environ.get("UVICORN_PROCESS_ID", None)
    )

    # If worker_id exists and is 0, or no worker_id, try to become master process
    if (worker_id is not None and worker_id == "0") or worker_id is None:
        try:
            # Try to create lock file
            if not os.path.exists(MASTER_PROCESS_FILE):
                with open(MASTER_PROCESS_FILE, "w") as f:
                    f.write(str(pid))
                return True
            else:
                # Read lock file and check if process exists
                with open(MASTER_PROCESS_FILE, "r") as f:
                    master_pid = f.read().strip()

                # Validate master_pid is a valid positive integer
                if not master_pid.isdigit() or int(master_pid) <= 0:
                    # Invalid PID in lock file, overwrite it
                    with open(MASTER_PROCESS_FILE, "w") as f:
                        f.write(str(pid))
                    return True

                master_pid_int = int(master_pid)

                # Try to confirm if the process exists
                # Note: os.kill with signal 0 doesn't send any signal,
                # it only checks if the process exists (standard Unix technique)
                try:
                    os.kill(master_pid_int, 0)
                    # Process exists, check if current process is master
                    return pid == master_pid_int
                except OSError:
                    # Process doesn't exist, update lock file and become master
                    with open(MASTER_PROCESS_FILE, "w") as f:
                        f.write(str(pid))
                    return True
        except Exception:
            return False
    return False


# Create synchronous Redis client for logging
def create_sync_redis_client():
    """Create a synchronous Redis client for logging purposes"""
    try:
        redis_params = {
            "host": settings.REDIS_HOST,
            "port": settings.REDIS_PORT,
            "decode_responses": True,
            "socket_connect_timeout": 2,
            "socket_timeout": 2,
        }

        if hasattr(settings, "REDIS_PASSWORD") and settings.REDIS_PASSWORD:
            redis_params["password"] = settings.REDIS_PASSWORD

        return redis.Redis(**redis_params)
    except Exception as e:
        print(f"Failed to create sync Redis client: {e}", file=sys.stderr)
        return None


# Redis log handler
class RedisLogHandler(logging.Handler):
    """Log handler using Redis as log queue"""

    def __init__(self, redis_key="app:logs", max_queue_size=10000):
        super().__init__()
        self.redis_key = redis_key
        self.max_queue_size = max_queue_size
        # Store pending logs for batch processing
        self._pending_logs = []
        self._max_batch_size = 100

    def emit(self, record):
        try:
            # Format log record
            log_entry = {
                "time": record.created,
                "name": record.name,
                "level": record.levelname,
                "message": self.format(record),
                "pathname": getattr(record, "pathname", ""),
                "lineno": getattr(record, "lineno", 0),
            }

            # Serialize log
            try:
                serialized_log = json.dumps(log_entry)

                # Add log to processing queue to avoid blocking or async call issues
                log_processor.add_log(serialized_log)
            except Exception as e:
                # Log to standard error output to avoid recursive logging
                print(f"Redis log handler error: {e}", file=sys.stderr)
        except Exception:
            self.handleError(record)


# Create a queue processing thread for later use
class LogQueueProcessor(threading.Thread):
    def __init__(self, redis_key="app:logs", daemon=True):
        super().__init__(daemon=daemon)
        self.redis_key = redis_key
        self.queue = []
        self.lock = threading.Lock()
        self.running = True
        self.redis_client = create_sync_redis_client()
        self.failed_log_handler = None
        self._init_failed_log_handler()

    def _init_failed_log_handler(self):
        """Initialize rotating file handler for failed logs"""
        try:
            failed_log_path = os.path.join(LOG_DIR, "redis_failed_logs.txt")
            # Use RotatingFileHandler with 10MB max size and 3 backup files
            self.failed_log_handler = logging.handlers.RotatingFileHandler(
                failed_log_path,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=3,
                encoding="utf-8",
            )
        except Exception as e:
            print(f"Failed to initialize failed log handler: {e}", file=sys.stderr)

    def add_log(self, log_data):
        with self.lock:
            self.queue.append(log_data)

    def run(self):
        while self.running:
            logs_to_process = self._get_queued_logs()
            self._process_logs(logs_to_process)
            time.sleep(0.1)

    def _get_queued_logs(self):
        """Get and clear queued logs"""
        with self.lock:
            if self.queue:
                logs = self.queue.copy()
                self.queue.clear()
                return logs
        return []

    def _process_logs(self, logs_to_process):
        """Process a batch of logs"""
        for log_data in logs_to_process:
            self._send_log_to_redis(log_data)

    def _send_log_to_redis(self, log_data):
        """Send a single log to Redis or backup"""
        try:
            if self.redis_client:
                self.redis_client.lpush(self.redis_key, log_data)
            else:
                self._write_failed_log(log_data)
        except Exception:
            self._write_failed_log(log_data)

    def _write_failed_log(self, log_data):
        """Write failed log to rotating file"""
        try:
            if self.failed_log_handler:
                # Create a dummy log record for the handler
                record = logging.LogRecord(
                    name="redis_failed",
                    level=logging.INFO,
                    pathname="",
                    lineno=0,
                    msg=log_data,
                    args=(),
                    exc_info=None,
                )
                self.failed_log_handler.emit(record)
            else:
                # Fallback to direct file write
                with open(os.path.join(LOG_DIR, "redis_failed_logs.txt"), "a") as f:
                    f.write(log_data + "\n")
        except Exception as e:
            print(f"Failed to write failed log: {e}", file=sys.stderr)

    def stop(self):
        self.running = False
        if self.redis_client:
            try:
                self.redis_client.close()
            except Exception:
                pass
        self.join(timeout=2)  # Wait at most 2 seconds for thread to complete


# Create and start log processing thread
log_processor = LogQueueProcessor()
log_processor.start()


# Create a multi-process safe file handler
class SafeTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """Multi-process safe log file handler"""

    def __init__(
        self,
        filename,
        when="h",
        interval=1,
        backup_count=0,
        encoding=None,
        delay=False,
        utc=False,
        at_time=None,
    ):
        super().__init__(
            filename,
            when=when,
            interval=interval,
            backupCount=backup_count,
            encoding=encoding,
            delay=delay,
            utc=utc,
            atTime=at_time,
        )
        # Avoid file permission conflicts in multi-process environment
        self.delay = True  # Delay file creation until first log is written
        self.mode = "a"  # Always append mode

    def _open(self):
        # File opening method that avoids multi-process conflicts
        return open(self.baseFilename, self.mode, encoding=self.encoding)


# Initialize Redis log handler
redis_handler = RedisLogHandler()

# Configure log formatters
console_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] [PID:%(process)d] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] [PID:%(process)d] %(name)s [%(pathname)s:%(lineno)d]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Apply formatter to Redis handler
redis_handler.setFormatter(file_formatter)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "console_formatter": {
            "format": "%(asctime)s [%(levelname)s] [PID:%(process)d] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "file_formatter": {
            "format": "%(asctime)s [%(levelname)s] [PID:%(process)d] %(name)s [%(pathname)s:%(lineno)d]: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": LOG_LEVEL,
            "formatter": "console_formatter",
        },
        "file": {
            "class": "app.core.log_config.SafeTimedRotatingFileHandler",
            "level": LOG_LEVEL,
            "formatter": "file_formatter",
            "filename": LOG_FILE,
            "when": "midnight",
            "interval": 1,
            "backup_count": 7,
            "encoding": "utf-8",
        },
        "sqlalchemy_file": {
            "class": "app.core.log_config.SafeTimedRotatingFileHandler",
            "level": SQLALCHEMY_LEVEL,
            "formatter": "file_formatter",
            "filename": SQLALCHEMY_LOG_FILE,
            "when": "midnight",
            "interval": 1,
            "backup_count": 7,
            "encoding": "utf-8",
        },
        "redis": {
            "()": "app.core.log_config.RedisLogHandler",
            "level": LOG_LEVEL,
        },
    },
    "loggers": {
        "": {
            "handlers": ["console", "file", "redis"],
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "sqlalchemy.engine": {
            "handlers": ["console", "sqlalchemy_file", "redis"],
            "level": SQLALCHEMY_LEVEL,
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["console", "file", "redis"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "uvicorn": {
            "handlers": ["console", "file", "redis"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}


def setup_logging():
    """Apply logging configuration"""
    # Ensure log directory exists
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    dictConfig(LOGGING_CONFIG)

    # Output initialization log only in master process
    if is_master_process():
        logging.getLogger("app.core.log_config").info(
            "Logging system initialized (master process)"
        )


def shutdown_logging():
    """Shutdown log handlers, no special shutdown needed in multi-process environment"""
    # Stop log processing thread
    log_processor.stop()

    # Output shutdown log only in master process
    if is_master_process():
        logging.getLogger("app.core.log_config").info(
            "Shutting down logging system (master process)"
        )
        # Clean up lock file
        try:
            if os.path.exists(MASTER_PROCESS_FILE):
                os.remove(MASTER_PROCESS_FILE)
        except Exception:
            pass
    logging.shutdown()
