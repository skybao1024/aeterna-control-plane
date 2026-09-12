import uuid
from datetime import UTC, datetime, timedelta
from typing import Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthBase:
    @staticmethod
    def create_access_token(
        subject: str, scope: str, expires_delta: Optional[timedelta] = None
    ) -> str:
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )

        to_encode = {
            "exp": expire,
            "sub": str(subject),
            "scope": scope,  # Add scope to differentiate permissions
            "jti": str(uuid.uuid4()),  # Unique identifier
        }
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    @staticmethod
    def create_refresh_token(
        subject: str, expires_delta: Optional[timedelta] = None
    ) -> str:
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(days=7)  # Default 7 days

        to_encode = {
            "exp": expire,
            "sub": str(subject),
            "jti": str(uuid.uuid4()),
            "scope": "refresh",
        }
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    @staticmethod
    def verify_token(token: str, scope: str = None) -> Optional[Dict]:
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            if scope and payload.get("scope") != scope:
                return None
            return payload
        except JWTError:
            return None

    @staticmethod
    def hash_token(token: str) -> str:
        return pwd_context.hash(token)

    @staticmethod
    def verify_token_hash(plain_token: str, hashed_token: str) -> bool:
        return pwd_context.verify(plain_token, hashed_token)
