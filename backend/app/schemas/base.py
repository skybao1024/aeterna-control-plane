import re
from datetime import datetime
from functools import wraps
from typing import Any, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class BaseResponseSchema(BaseSchema):
    id: int
    created_at: datetime = Field(default=0)
    updated_at: datetime = Field(default=0)

    def set_padded_id(self, pad_length: int = 4):
        """Set padded_id for current object"""
        if self.id is not None:
            self.padded_id = str(self.id).zfill(pad_length)
        return self

    def process_nested_padded_ids(self, pad_length: int = 4):
        """Process padded_id for current object and all nested objects"""
        # Process current object
        self.set_padded_id(pad_length)

        # Iterate through all fields to find nested objects
        for field_name, field_value in self.__dict__.items():
            # Skip special fields
            if field_name.startswith("_"):
                continue

            # Process nested BaseResponseSchema objects
            if isinstance(field_value, BaseResponseSchema):
                field_value.process_nested_padded_ids(pad_length)

            # Process nested lists
            elif isinstance(field_value, list):
                for item in field_value:
                    if isinstance(item, BaseResponseSchema):
                        item.process_nested_padded_ids(pad_length)

        return self


def format_datetime(dt: Optional[datetime]) -> str:
    """Convert datetime object to ISO format string, None to empty string"""
    if dt is None:
        return ""
    return dt.isoformat()


def to_timestamp(v: Any) -> int:
    """Convert various time formats to timestamp integer, None to 0"""
    if isinstance(v, datetime):
        return int(v.timestamp())
    elif v is None:
        return 0
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError("time fields must be valid datetime or a number")


def add_padded_id(pad_length: int = 4):
    """
    Decorator to add padded ID handling to Pydantic model

    Args:
        pad_length (int, optional): ID padding length. Defaults to 4.

    Returns:
        Decorated response model class
    """

    def decorator(cls: Type):
        # Dynamically add padded_id field
        if not hasattr(cls, "padded_id"):
            cls.padded_id = Field(default=None, init=False)

        # Define formatting method
        def format_padded_id(id: int) -> str:
            """Convert ID to padded string of specified length"""
            return str(id).zfill(pad_length)

        # Save formatting method
        setattr(cls, "format_padded_id", staticmethod(format_padded_id))

        # Modify model_validate method
        original_validate = getattr(cls, "model_validate", None)

        @classmethod
        @wraps(
            original_validate or (lambda cls, obj: cls.model_construct(**obj.__dict__))
        )
        def enhanced_validate(cls, obj: Any):
            # Call original validation method
            if original_validate and original_validate != enhanced_validate:
                instance = original_validate(obj)
            else:
                instance = cls.model_construct(**obj.__dict__)

            # Dynamically set padded_id
            padded_id_method = getattr(cls, "format_padded_id", None)
            if padded_id_method:
                instance.padded_id = padded_id_method(instance.id)

            return instance

        # Update class model_validate method
        cls.model_validate = enhanced_validate

        return cls

    return decorator
