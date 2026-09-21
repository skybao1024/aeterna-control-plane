from typing import Any

from fastapi import HTTPException


class APIException(HTTPException):
    def __init__(
        self,
        code: int = 10000,
        message: str = "API exception",
        status_code: int = 400,
        data: Any = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.code = code  # Business error code
        self.data = data  # Optional additional data


# Common exception types
class ValidationError(APIException):
    def __init__(
        self,
        message: str = "Validation error",
        data: Any = None,
    ):
        super().__init__(code=1001, message=message, status_code=400, data=data)


class AuthenticationError(APIException):
    def __init__(
        self,
        message: str = "Authentication failed",
        data: Any = None,
    ):
        super().__init__(code=1002, message=message, status_code=401, data=data)


class AuthorizationError(APIException):
    def __init__(
        self,
        message: str = "Permission denied",
        data: Any = None,
    ):
        super().__init__(code=1003, message=message, status_code=403, data=data)


class NotFoundError(APIException):
    def __init__(
        self,
        message: str = "Resource not found",
        data: Any = None,
    ):
        super().__init__(code=1004, message=message, status_code=404, data=data)


class ServerError(APIException):
    def __init__(
        self,
        message: str = "Internal server error",
        data: Any = None,
    ):
        super().__init__(code=1005, message=message, status_code=500, data=data)


class ForeignKeyViolationError(APIException):
    def __init__(
        self,
        message: str = "Resource is still referenced and cannot be removed",
        data: Any = None,
    ):
        super().__init__(code=1006, message=message, status_code=400, data=data)
