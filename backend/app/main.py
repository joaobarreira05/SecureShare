from contextlib import asynccontextmanager
from fastapi import FastAPI
from .core.database import create_db_and_tables
from .core.settings import settings
from .models.User import User # Import models to register them with SQLModel
from .models.JWTAuthToken import JWTAuthToken
from .models.Department import Department
from .models.Audit import AuditLog
from .core.init_db import init_db

from .auth.router import router as auth_router
from .users.router import router as users_router
from .departments.router import router as departments_router
from .transfers.router import router as transfers_router
from .audit.router import router as audit_router
from .user.router import router as user_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    init_db()
    yield



app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(departments_router)
app.include_router(user_router)
app.include_router(transfers_router)
app.include_router(audit_router)

@app.get("/")
def read_root():
    return {"message": f"Welcome to {settings.PROJECT_NAME}"}
