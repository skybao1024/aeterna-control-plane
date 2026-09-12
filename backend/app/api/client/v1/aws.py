from typing import Dict
from fastapi import APIRouter, Depends

from app.api.client.deps import get_current_user
from app.exceptions.http_exceptions import APIException
from app.models.user import User
from app.schemas.client.aws import (PresignedUrlRequest)
from app.schemas.response import ApiResponse
from app.services.common.s3_service import S3Service, get_s3_service

router = APIRouter()


@router.post("/presigned-upload-url", response_model=ApiResponse[Dict])
async def generate_presigned_upload_url(
    request: PresignedUrlRequest,
    current_user: User = Depends(get_current_user),
    s3_service: S3Service = Depends(get_s3_service),
):
    """
    Generate S3 presigned upload URL

    - **file_name**: File name with extension
    - **file_type**: File MIME type
    - **file_size**: File size in bytes
    - **module**: Module name (positions, interviews, etc.)
    - **module_id**: Module record ID (optional)
    - **sub_path**: Sub-path type (jd, cv, cover-letter)
    """
    # Validate file size (max 10MB)
    max_size = 10 * 1024 * 1024  # 10MB
    if request.file_size > max_size:
        raise APIException(
            status_code=400,
            message=f"File size exceeds maximum limit of {max_size / (1024 * 1024)}MB",
        )

    # Validate file type
    allowed_types = ["pdf", "docx"]
    if not s3_service.validate_file_type(request.file_name, allowed_types):
        raise APIException(
            status_code=400,
            message=f"Unsupported file type. Allowed types: {', '.join(allowed_types)}",
        )

    # Generate file key
    file_key = s3_service.generate_file_key(
        user_id=current_user.id,
        file_name=request.file_name,
        module=request.module,
        sub_path=request.sub_path,
        module_id=request.module_id,
    )

    # Generate presigned URL
    result = s3_service.generate_presigned_upload_url(
        file_key=file_key,
        file_type=request.file_type,
        expires_in=900,  # 15 minutes
        max_file_size=max_size,
    )

    return ApiResponse.success(data=result)


@router.get("/presigned-download-url", response_model=ApiResponse[Dict])
async def generate_presigned_download_url(
    file_key: str,
    current_user: User = Depends(get_current_user),
    s3_service: S3Service = Depends(get_s3_service),
):
    """
    Generate S3 presigned download URL

    - **file_key**: S3 file key
    """
    # Validate if file key belongs to current user
    if not file_key.startswith(f"users/{current_user.id}/"):
        raise APIException(
            status_code=403,
            message="Access denied: You don't have permission to access this file",
        )

    download_url = s3_service.generate_presigned_download_url(file_key)

    return ApiResponse.success(
        data={
            "download_url": download_url,
            "file_key": file_key,
            "expires_in": 3600,  # 1 hour
        }
    )
