from typing import Literal, Optional

from pydantic import BaseModel, Field


class PresignedUrlRequest(BaseModel):
    """Request schema for presigned URL generation"""

    file_name: str = Field(..., description="File name with extension")
    file_type: str = Field(..., description="File MIME type, e.g., 'application/pdf'")
    file_size: int = Field(..., description="File size in bytes", gt=0)
    module: Optional[str] = Field(
        None, description="Module name, e.g., 'positions', 'interviews'"
    )
    module_id: Optional[int] = Field(
        None, description="Module record ID, e.g., position_id"
    )
    sub_path: Optional[Literal["jd", "cv", "cover-letter"]] = Field(
        None,
        description="Sub-path type. Accepted values: 'jd' (job description), 'cv' (curriculum vitae), 'cover-letter' (cover letter)",
        json_schema_extra={"enum": ["jd", "cv", "cover-letter"]},
    )


class PresignedUrlResponse(BaseModel):
    """Response schema for presigned URL"""

    presigned_url: str = Field(..., description="S3 presigned upload URL")
    file_key: str = Field(..., description="S3 file key")
    expires_in: int = Field(..., description="URL expiration time in seconds")
    max_file_size: int = Field(..., description="Maximum file size in bytes")


class PresignedDownloadUrlResponse(BaseModel):
    """Response schema for presigned download URL"""

    download_url: str = Field(..., description="S3 presigned download URL")
    file_key: str = Field(..., description="S3 file key")
    expires_in: int = Field(..., description="URL expiration time in seconds")
