import asyncio
from math import ceil
from typing import Any, Callable, Dict, Generic, List, Type, TypeVar

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.engine.result import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

T = TypeVar("T")


class Paginator(Generic[T]):
    """Laravel-style paginator"""

    def __init__(self, query: Select, db: AsyncSession):
        self.query = query
        self.db = db
        self._items = None
        self._total = None
        self._per_page = 10
        self._page = 1
        self._last_page = None
        self._processors = []
        self._result = None  # Save original query result

    async def paginate(self, page: int = 1, per_page: int = 10) -> "Paginator":
        """Execute paginated query"""
        self._page = max(1, page)
        self._per_page = max(1, per_page)

        # Calculate total count
        if self._total is None:
            total_query = select(func.count()).select_from(self.query.subquery())
            self._total = await self.db.scalar(total_query)

        # Calculate last page
        self._last_page = (
            ceil(self._total / self._per_page) if self._per_page > 0 else 0
        )

        # Apply pagination
        paginated_query = self.query.offset((self._page - 1) * self._per_page).limit(
            self._per_page
        )

        # Execute query
        self._result = await self.db.execute(paginated_query)

        # Try to distinguish single entity queries from multi-column queries
        keys = list(self._result.keys())  # Convert to list for subsequent use
        if len(keys) == 1:
            # Single entity query
            self._items = self._result.scalars().all()
        else:
            # Multi-column query
            self._items = self._process_multi_column_result(keys)

        # Apply all processors (modified for async processing)
        for processor in self._processors:
            if asyncio.iscoroutinefunction(processor):
                self._items = await processor(self._items)
            else:
                self._items = processor(self._items)

        return self

    def _process_multi_column_result(self, keys: List[str]) -> List[Any]:
        """Process multi-column query results"""
        if not self._result:
            return []

        rows = self._result.all()
        if not rows:
            return []

        processed_items = []

        for row in rows:
            if isinstance(row, Row) or isinstance(row, tuple):
                # Get main entity (first column)
                main_entity = row[0]

                # Set additional columns as attributes of main entity
                for i in range(1, len(keys)):
                    # Use column name as attribute name
                    attr_name = keys[i]
                    setattr(main_entity, attr_name, row[i])

                processed_items.append(main_entity)
            else:
                # Single column query
                processed_items.append(row)

        return processed_items

    def process(self, callback: Callable[[List[Any]], List[Any]]) -> "Paginator":
        """Add processor function"""
        self._processors.append(callback)
        return self

    def map(self, model_class: Type[BaseModel]) -> "Paginator":
        """Map to Pydantic model"""

        def mapper(items):
            mapped_items = []
            for item in items:
                # Extract entity attributes
                item_dict = {}

                # Add all non-internal attributes
                for key, value in vars(item).items():
                    if not key.startswith("_"):
                        item_dict[key] = value

                # Handle associated objects
                for attr_name in dir(item):
                    if attr_name.startswith("_") or attr_name in item_dict:
                        continue

                    try:
                        attr_value = getattr(item, attr_name)
                        # Check if it's an associated object
                        if (
                            hasattr(attr_value, "__table__")
                            or attr_name in model_class.__annotations__
                        ):
                            item_dict[attr_name] = attr_value
                    except Exception:
                        # Ignore inaccessible attributes
                        pass

                # Try using model_validate to create instance
                try:
                    mapped_item = model_class.model_validate(item_dict)
                except Exception as e:
                    # Fallback method: direct construction
                    mapped_item = model_class.model_construct(**item_dict)

                mapped_items.append(mapped_item)

            return mapped_items

        self._items = mapper(self._items)
        return self

    @property
    def items(self) -> List[Any]:
        """Get items for current page"""
        return self._items or []

    @property
    def total(self) -> int:
        """Get total count"""
        return self._total or 0

    @property
    def per_page(self) -> int:
        """Items per page"""
        return self._per_page

    @property
    def current_page(self) -> int:
        """Current page number"""
        return self._page

    @property
    def last_page(self) -> int:
        """Last page number"""
        return self._last_page or 0

    @property
    def has_more(self) -> bool:
        """Whether there are more pages"""
        return self._page < (self._last_page or 0)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "items": self.items,
            "total": self.total,
            "per_page": self.per_page,
            "current_page": self.current_page,
            "last_page": self.last_page,
            "has_more": self.has_more,
        }

    def to_json(self) -> Dict:
        """Convert to JSON-serializable dictionary"""
        return jsonable_encoder(self.to_dict())

    def response(
        self, message: str = "Success", code: int = 200, http_code: int = 200
    ) -> JSONResponse:
        """Create API response"""
        return JSONResponse(
            content={"code": code, "message": message, "data": self.to_json()},
            status_code=http_code,
        )
