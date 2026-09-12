from typing import List, Optional

from fastapi import status
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import AuthBase
from app.exceptions.http_exceptions import APIException
from app.models.admin import Admin
from app.schemas.backoffice.admin import AdminCreate, AdminResponse


class AdminService:
    async def create_admin(
        self, db: AsyncSession, admin_data: AdminCreate
    ) -> AdminResponse:
        """Create new admin"""
        # Check if email already exists
        email_query = select(Admin).where(Admin.email == admin_data.email)
        result = await db.execute(email_query)
        if result.scalar_one_or_none():
            raise APIException(
                status_code=status.HTTP_400_BAD_REQUEST, message="Email already exists"
            )

        # Create new admin
        hashed_password = AuthBase.hash_token(admin_data.password)
        admin = Admin(
            email=admin_data.email,
            first_name=admin_data.first_name,
            last_name=admin_data.last_name,
            password=hashed_password,
            is_active=admin_data.is_active,
            role="superadmin",
        )

        db.add(admin)
        await db.flush()
        await db.refresh(admin)

        return AdminResponse.model_validate(admin)

    async def get_admin(
        self, db: AsyncSession, admin_id: int
    ) -> Optional[AdminResponse]:
        """Get admin details"""
        admin_query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(admin_query)
        admin = result.scalar_one_or_none()

        if not admin:
            return None

        return AdminResponse.model_validate(admin)

    async def get_admin_by_email(self, db: AsyncSession, email: str) -> Optional[Admin]:
        """Get admin by email"""
        admin_query = select(Admin).where(Admin.email == email)
        result = await db.execute(admin_query)
        return result.scalar_one_or_none()

    async def list_admins(
        self,
        db: AsyncSession,
        offset: int = 0,
        limit: int = 100,
        email: str = None,
        sort_by: str = None,
        sort_order: str = "desc",
    ) -> List[AdminResponse]:
        """Get all admins list"""
        admin_query = (
            await self.get_admins_query(db, email, sort_by, sort_order)
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(admin_query)
        admins = result.scalars().all()

        return [AdminResponse.model_validate(admin) for admin in admins]

    async def get_admins_query(
        self,
        db: AsyncSession,
        email: str = None,
        sort_by: str = None,
        sort_order: str = "desc",
    ):
        """Get admin query object for pagination

        Args:
            db: Database session
            email: Optional email filter condition
            sort_by: Sort field, defaults to created_at
            sort_order: Sort direction, asc or desc
        """
        query = select(Admin)

        # Add filter conditions
        if email:
            query = query.where(Admin.email.ilike(f"%{email}%"))

        # Add sorting
        if sort_by == "email":
            if sort_order.lower() == "asc":
                query = query.order_by(Admin.email.asc())
            else:
                query = query.order_by(Admin.email.desc())
        else:  # Default sort by creation time
            if sort_order.lower() == "asc":
                query = query.order_by(Admin.created_at.asc())
            else:
                query = query.order_by(Admin.created_at.desc())

        return query

    async def update_admin(
        self, db: AsyncSession, admin_id: int, admin_data: dict
    ) -> Optional[AdminResponse]:
        """Update admin information"""
        # First check if admin exists
        admin_query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(admin_query)
        admin = result.scalar_one_or_none()

        if not admin:
            return None

        update_data = {}

        # Check if email needs to be updated and if it already exists
        if "email" in admin_data and admin_data["email"] != admin.email:
            email_query = select(Admin).where(
                Admin.email == admin_data["email"], Admin.id != admin_id
            )
            result = await db.execute(email_query)
            if result.scalar_one_or_none():
                raise APIException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="Email already exists",
                )
            update_data["email"] = admin_data["email"]

        # If password update, need to hash it
        if "password" in admin_data:
            update_data["password"] = AuthBase.hash_token(admin_data["password"])

        # Update first name
        if "first_name" in admin_data:
            update_data["first_name"] = admin_data["first_name"]

        # Update last name
        if "last_name" in admin_data:
            update_data["last_name"] = admin_data["last_name"]

        # Update active status
        if "is_active" in admin_data:
            update_data["is_active"] = admin_data["is_active"]

        # Execute update
        if update_data:
            stmt = update(Admin).where(Admin.id == admin_id).values(**update_data)
            await db.execute(stmt)

            # Re-fetch updated admin information
            admin_query = select(Admin).where(Admin.id == admin_id)
            result = await db.execute(admin_query)
            admin = result.scalar_one_or_none()

        return AdminResponse.model_validate(admin)

    async def delete_admin(self, db: AsyncSession, admin_id: int) -> bool:
        """Delete admin"""
        # First check if admin exists
        admin_query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(admin_query)
        admin = result.scalar_one_or_none()

        if not admin:
            return False

        # First delete associated admin_tokens
        from app.models.token import AdminToken

        delete_tokens_stmt = delete(AdminToken).where(AdminToken.admin_id == admin_id)
        await db.execute(delete_tokens_stmt)

        # Execute admin deletion
        stmt = delete(Admin).where(Admin.id == admin_id)
        await db.execute(stmt)

        return True

    async def change_password(
        self, db: AsyncSession, admin_id: int, current_password: str, new_password: str
    ) -> bool:
        """Change admin password"""
        # First check if admin exists
        admin_query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(admin_query)
        admin = result.scalar_one_or_none()

        if not admin:
            return False

        # Verify current password
        if not AuthBase.verify_token_hash(current_password, admin.password):
            raise APIException(
                status_code=status.HTTP_400_BAD_REQUEST,
                message="Current password is incorrect",
            )

        # Update password
        hashed_password = AuthBase.hash_token(new_password)
        stmt = (
            update(Admin).where(Admin.id == admin_id).values(password=hashed_password)
        )
        await db.execute(stmt)

        return True

    async def reset_password(
        self, db: AsyncSession, admin_id: int, new_password: str
    ) -> bool:
        """Reset admin password (only admin themselves or superadmin can operate)"""
        # First check if admin exists
        admin_query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(admin_query)
        admin = result.scalar_one_or_none()

        if not admin:
            return False

        # Update password
        hashed_password = AuthBase.hash_token(new_password)
        stmt = (
            update(Admin).where(Admin.id == admin_id).values(password=hashed_password)
        )
        await db.execute(stmt)

        return True


def get_admin_service() -> AdminService:
    """Get AdminService instance (dependency injection)"""
    return AdminService()
