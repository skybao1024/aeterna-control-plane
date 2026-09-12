from typing import Any, Dict, Generic, Optional, TypeVar

from fastapi import Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Generic API response model"""

    code: int = Field(200, description="Business status code, 200 indicates success")
    message: str = Field("Success", description="Response message")
    data: Optional[T] = Field(None, description="Response data")

    class Config:
        json_schema_extra = {
            "example": {
                "code": 200,
                "message": "Success",
                "data": {"key": "value"},
            }
        }

    @staticmethod
    def success(
        data: Any = None,
        message: str = "Success",
        body_code: int = 200,
        http_code: int = status.HTTP_200_OK,
        headers: Dict = None,
    ) -> JSONResponse:
        """Success response"""
        response_data = {
            "code": body_code,
            "message": message,
            "data": jsonable_encoder(data) if data is not None else None,
        }
        return JSONResponse(
            content=response_data, status_code=http_code, headers=headers
        )

    @staticmethod
    def success_without_data(
        http_code: int = status.HTTP_204_NO_CONTENT, headers: Dict = None
    ) -> Response:
        """Success response without data"""
        return Response(status_code=http_code, headers=headers)

    @staticmethod
    def failed(
        message: str,
        body_code: int,
        http_code: int = status.HTTP_400_BAD_REQUEST,
        data: Any = None,
        headers: Dict = None,
    ) -> JSONResponse:
        """Failed response"""
        response_data = {"code": body_code, "message": message}
        if data is not None:
            response_data["data"] = jsonable_encoder(data)
        return JSONResponse(
            content=response_data, status_code=http_code, headers=headers
        )
