from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class UserResponse(BaseModel):
    """
    User response schema - secure version

    SECURITY: Does not include sensitive fields (hashed_password, google_id, etc.)
    """

    id: int
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar: Optional[str] = None
    gender: Optional[str] = None
    is_active: bool
    is_verified: bool
    auth_provider: str
    last_active_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True  # Pydantic v2 (was orm_mode in v1)


class UserProfileUpdate(BaseModel):
    """Update user profile request"""

    first_name: Optional[str] = None
    last_name: Optional[str] = None
    gender: Optional[str] = None
    avatar: Optional[str] = None
