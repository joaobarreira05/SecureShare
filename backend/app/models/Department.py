from datetime import datetime
from sqlmodel import Field, SQLModel

class Department(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DepartmentCreate(SQLModel):
    name: str
    description: str | None = None

class DepartmentResponse(SQLModel):
    id: int
    name: str
    description: str | None
    created_at: datetime
