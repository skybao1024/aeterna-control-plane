from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys
import glob
import importlib
from pathlib import Path

# Get project root directory absolute path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Add project root directory to Python path
sys.path.append(BASE_DIR)

# Import project configuration
from app.core.config import settings
from app.db.models import Base


def import_all_models():
    """Automatically import all models from the models directory"""
    models_path = Path(BASE_DIR) / "app" / "models"
    model_files = glob.glob(str(models_path / "*.py"))

    for model_file in model_files:
        if not model_file.endswith("__init__.py"):
            module_name = Path(model_file).stem
            importlib.import_module(f"app.models.{module_name}")


# Import all models
import_all_models()

# this is the Alembic Config object
config = context.config

# Override alembic.ini database URL with project settings
config.set_main_option(
    "sqlalchemy.url",
    f"postgresql+psycopg2://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# import all models here
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
