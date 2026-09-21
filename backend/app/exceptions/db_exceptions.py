from functools import wraps

from sqlalchemy.exc import IntegrityError

from app.exceptions.http_exceptions import ForeignKeyViolationError


def handle_db_exceptions(func):
    """
    Decorator for handling exceptions in database operations, especially foreign key constraint violations

    Usage example:
    @handle_db_exceptions
    async def delete_item(db: AsyncSession, item_id: int):
        # Deletion operation code
    """

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except IntegrityError as exc:
            if getattr(exc.orig, "sqlstate", None) == "23503":
                raise ForeignKeyViolationError() from exc
            raise

    return wrapper
