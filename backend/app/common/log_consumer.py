import asyncio
import json
import logging
import os
import time
from logging.handlers import TimedRotatingFileHandler

from app.services.common.redis import RedisClient


async def consume_logs_forever(redis_key="app:logs"):
    """
    Consume logs from Redis queue and write to file (async version)
    """
    # Create independent Redis client instance, ensure it runs in the correct event loop
    local_redis_client = RedisClient()

    # Fix BASE_DIR calculation to be consistent with log_config.py
    # Current file is at app/common/log_consumer.py, need to go up three levels to reach project root
    script_path = os.path.abspath(__file__)
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(script_path), "../.."))

    log_dir = os.path.join(BASE_DIR, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, f"app_{time.strftime('%Y%m%d')}.log")
    sql_log_file = os.path.join(log_dir, f"sqlalchemy_{time.strftime('%Y%m%d')}.log")

    file_handler = TimedRotatingFileHandler(
        filename=log_file, when="midnight", interval=1, backupCount=7, encoding="utf-8"
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s [%(pathname)s:%(lineno)d]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    sql_file_handler = TimedRotatingFileHandler(
        filename=sql_log_file,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
    )
    sql_file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s [%(pathname)s:%(lineno)d]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    try:
        while True:
            try:
                result = await local_redis_client.brpop(redis_key, timeout=1)
                if result:
                    _, log_data = result
                    log_entry = json.loads(log_data)
                    record = logging.LogRecord(
                        name=log_entry["name"],
                        level=getattr(logging, log_entry["level"]),
                        pathname=log_entry.get("pathname", ""),
                        lineno=log_entry.get("lineno", 0),
                        msg=log_entry["message"],
                        args=(),
                        exc_info=None,
                    )
                    if log_entry["name"].startswith("sqlalchemy"):
                        sql_file_handler.handle(record)
                    else:
                        file_handler.handle(record)
            except Exception as e:
                print(f"[LogConsumer] Error processing log: {e}")
                await asyncio.sleep(1)
    finally:
        # Ensure Redis connection is closed
        await local_redis_client.close()
