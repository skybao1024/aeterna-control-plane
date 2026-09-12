import re
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.client.user import UserResponse

# ==================== Registration ====================


def validate_password_strength(password: str) -> str:
    """
    Validate password strength

    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*(),.?":{}|<>)
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")

    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError(
            'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)'
        )

    return password


class SignUp(BaseModel):
    """Registration request - Step 1: Create account and send verification code"""

    email: EmailStr = Field(..., description="Email address")
    password: str = Field(
        ...,
        min_length=8,
        description="Password (at least 8 characters, must include uppercase, lowercase, digit, and special character)",
    )
    first_name: Optional[str] = Field(None, max_length=100, description="First name")
    last_name: Optional[str] = Field(None, max_length=100, description="Last name")

    @validator("password")
    def validate_password(cls, v):
        return validate_password_strength(v)


class SignUpResponse(BaseModel):
    """Registration response"""

    email: str
    message: str = "Verification code has been sent to your email"
    require_verification: bool = True


class VerifyEmail(BaseModel):
    """Email verification request - Step 2: Verify email"""

    email: EmailStr = Field(..., description="Email address")
    code: str = Field(
        ..., min_length=4, max_length=4, description="4-digit verification code"
    )

    @validator("code")
    def validate_code_format(cls, v):
        if not v.isdigit():
            raise ValueError("Verification code must be a 4-digit number")
        return v


class ResendVerification(BaseModel):
    """Resend verification code request"""

    email: EmailStr = Field(..., description="Email address")


# ==================== Login ====================


class Login(BaseModel):
    """Email and password login request"""

    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")


class GoogleLogin(BaseModel):
    """Google SSO login request"""

    id_token: str = Field(..., description="Google ID Token")


class Token(BaseModel):
    """Token response"""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: Optional[UserResponse] = None  # SECURITY: Use secure UserResponse schema


class VerifyEmailResponse(BaseModel):
    """Email verification response"""

    message: str = "Email verified successfully"
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ResendVerificationResponse(BaseModel):
    """Resend verification code response"""

    message: str = "Verification code has been sent"
    cooldown_seconds: int = 60


class RefreshToken(BaseModel):
    """Refresh token request"""

    refresh_token: str = Field(..., description="Refresh token")


class Logout(BaseModel):
    """Logout request"""

    refresh_token: str = Field(..., description="Refresh token")


# ==================== Password Reset ====================


class RequestPasswordReset(BaseModel):
    """Request password reset"""

    email: EmailStr = Field(..., description="Email address")


class ResetPassword(BaseModel):
    """Reset password"""

    token: str = Field(..., description="Reset token")
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password (at least 8 characters, must include uppercase, lowercase, digit, and special character)",
    )

    @validator("new_password")
    def validate_password(cls, v):
        return validate_password_strength(v)


# ==================== Response ====================


class MessageResponse(BaseModel):
    """Generic message response"""

    message: str
