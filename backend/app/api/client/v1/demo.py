import logging

from fastapi import APIRouter

from app.schemas.response import ApiResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()


# Create PDF and process in background
@router.post("")
async def demo():
    return ApiResponse.success_without_data()
