from typing import Any, Optional

from fastapi import HTTPException

from app.common.language import get_message


class APIException(HTTPException):
    def __init__(
        self,
        code: int = 10000,
        message: str = "API exception",
        status_code: int = 400,
        data: Any = None,
        language: Optional[str] = None,
    ) -> None:
        # Translate the message based on the language
        translated_message = get_message(message, language)
        super().__init__(status_code=status_code, detail=translated_message)
        self.code = code  # Business error code
        self.data = data  # Optional additional data


# Common exception types
class ValidationError(APIException):
    def __init__(
        self,
        message: str = "Validation error",
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1001, message=message, status_code=400, data=data, language=language
        )


class AuthenticationError(APIException):
    def __init__(
        self,
        message: str = "Authentication failed",
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1002, message=message, status_code=401, data=data, language=language
        )


class AuthorizationError(APIException):
    def __init__(
        self,
        message: str = "Permission denied",
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1003, message=message, status_code=403, data=data, language=language
        )


class NotFoundError(APIException):
    def __init__(
        self,
        message: str = "Resource not found",
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1004, message=message, status_code=404, data=data, language=language
        )


class ServerError(APIException):
    def __init__(
        self,
        message: str = "Internal server error",
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1005, message=message, status_code=500, data=data, language=language
        )


class ForeignKeyViolationError(APIException):
    def __init__(
        self,
        message: str = 'It is linked to trips or other resources. Please mark it as "inactive" to hide it from users',
        data: Any = None,
        language: Optional[str] = None,
    ):
        super().__init__(
            code=1006, message=message, status_code=400, data=data, language=language
        )
