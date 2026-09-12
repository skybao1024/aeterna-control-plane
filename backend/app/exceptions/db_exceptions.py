import re
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
        except IntegrityError as e:
            error_msg = str(e)
            # Check if it's a foreign key constraint error
            if (
                "foreign key constraint fails" in error_msg.lower()
                or "FOREIGN KEY constraint failed" in error_msg
            ):
                # Try to extract related table name from error message
                referenced_table = extract_referenced_table(error_msg)
                if referenced_table:
                    raise ForeignKeyViolationError(
                        message=f'It is linked to trips or other resources. Please mark it as "inactive" to hide it from users'
                    )
                else:
                    raise ForeignKeyViolationError()
            # Re-raise original exception
            raise

    return wrapper


def extract_referenced_table(error_message: str) -> str:
    """
    Extract referenced table name from error message
    """
    # MySQL foreign key error message format: "FOREIGN KEY constraint failed (table_name, CONSTRAINT ...)"
    # or "foreign key constraint fails (`database`.`table`, CONSTRAINT ...)"
    try:
        # Try to match MySQL error format
        match = re.search(r"constraint fails \(`[^`]*`.`([^`]*)`", error_message)
        if match:
            return match.group(1)

        # Try to match SQLite error format
        match = re.search(r"FOREIGN KEY constraint failed \(([^,]*)", error_message)
        if match:
            return match.group(1)

        return ""
    except:
        return ""
