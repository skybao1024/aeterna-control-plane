import mimetypes
from typing import Optional
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError

from app.core.config import settings
from app.exceptions.http_exceptions import APIException


class S3Service:
    """S3 file service - provides file upload, download and management functionality"""

    def __init__(self):
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        self.bucket_name = settings.AWS_BUCKET_NAME

    def generate_file_key(
        self,
        user_id: int,
        file_name: str,
        module: Optional[str] = None,
        sub_path: Optional[str] = None,
        module_id: Optional[int] = None,
    ) -> str:
        """
        Generate standardized S3 file key

        Args:
            user_id: User ID
            file_name: Original file name
            module: Module name (positions, interviews, etc.) - optional
            sub_path: Sub-path (jd, cv, cover_letter, etc.) - optional
            module_id: Module record ID (optional, e.g., position_id)

        Returns:
            Standardized file key path
        """
        # Get file extension
        file_ext = file_name.split(".")[-1].lower() if "." in file_name else ""

        # Generate unique filename
        unique_filename = f"{uuid4()}.{file_ext}" if file_ext else str(uuid4())

        # Build file path based on available parameters
        path_parts = [f"users/{user_id}"]

        if module:
            path_parts.append(module)
            if module_id:
                path_parts.append(str(module_id))

        if sub_path:
            path_parts.append(sub_path)

        path_parts.append(unique_filename)

        return "/".join(path_parts)

    def generate_presigned_upload_url(
        self,
        file_key: str,
        file_type: str,
        expires_in: int = 900,  # 15 minutes
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
    ) -> dict:
        """
        Generate S3 presigned upload URL

        Args:
            file_key: S3 file key
            file_type: File MIME type
            expires_in: URL expiration time (seconds)
            max_file_size: Maximum file size (bytes)

        Returns:
            {
                "presigned_url": "...",
                "file_key": "...",
                "expires_in": 900
            }
        """
        try:
            # Generate presigned URL
            presigned_url = self.s3_client.generate_presigned_url(
                "put_object",
                Params={
                    "Bucket": self.bucket_name,
                    "Key": file_key,
                    "ContentType": file_type,
                },
                ExpiresIn=expires_in,
                HttpMethod="PUT",
            )

            return {
                "presigned_url": presigned_url,
                "file_key": file_key,
                "expires_in": expires_in,
                "max_file_size": max_file_size,
            }

        except ClientError as e:
            raise APIException(
                status_code=500, message=f"Failed to generate presigned URL: {str(e)}"
            )

    def generate_presigned_download_url(
        self, file_key: str, expires_in: int = 3600  # 1 hour
    ) -> str:
        """
        Generate S3 presigned download URL

        Args:
            file_key: S3 file key
            expires_in: URL expiration time (seconds)

        Returns:
            Presigned download URL
        """
        try:
            presigned_url = self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": file_key},
                ExpiresIn=expires_in,
            )
            return presigned_url

        except ClientError as e:
            raise APIException(
                status_code=500, message=f"Failed to generate download URL: {str(e)}"
            )

    def get_file_url(self, file_key: str) -> str:
        """
        Get file public access URL

        Args:
            file_key: S3 file key

        Returns:
            File S3 URL
        """
        if settings.AWS_ENDPOINT:
            return f"{settings.AWS_ENDPOINT}/{file_key}"
        else:
            if settings.AWS_REGION and settings.AWS_REGION.startswith("cn-"):
                return f"https://{self.bucket_name}.s3.{settings.AWS_REGION}.amazonaws.com.cn/{file_key}"
            else:
                return f"https://{self.bucket_name}.s3.{settings.AWS_REGION}.amazonaws.com/{file_key}"

    def delete_file(self, file_key: str) -> bool:
        """
        Delete S3 file

        Args:
            file_key: S3 file key

        Returns:
            Whether deletion was successful
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=file_key)
            return True

        except ClientError as e:
            raise APIException(
                status_code=500, message=f"Failed to delete file: {str(e)}"
            )

    def validate_file_type(self, file_name: str, allowed_types: list) -> bool:
        """
        Validate file type

        Args:
            file_name: File name
            allowed_types: List of allowed file types (e.g., ['pdf', 'docx'])

        Returns:
            Whether file type is allowed
        """
        file_ext = file_name.split(".")[-1].lower() if "." in file_name else ""
        return file_ext in allowed_types

    def get_mime_type(self, file_name: str) -> str:
        """
        Get file MIME type

        Args:
            file_name: File name

        Returns:
            MIME type
        """
        mime_type, _ = mimetypes.guess_type(file_name)
        return mime_type or "application/octet-stream"


def get_s3_service() -> S3Service:
    """Get S3Service instance (dependency injection)"""
    return S3Service()
