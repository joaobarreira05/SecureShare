from fastapi import APIRouter, Depends, status
from sqlmodel import Session
from ..core.database import get_session
from ..auth.service import get_current_active_admin
from ..models.User import User
from ..models.Department import DepartmentCreate, DepartmentResponse
from .service import create_department, get_all_departments, delete_department

router = APIRouter(prefix="/departments", tags=["departments"])

@router.post("", response_model=DepartmentResponse, status_code=status.HTTP_201_CREATED)
async def create_new_department(
    department: DepartmentCreate,
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    Create a new department (Admin only).
    """
    return create_department(session, department)

@router.get("", response_model=list[DepartmentResponse])
async def read_departments(
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    List all departments (Admin only).
    """
    return get_all_departments(session)

@router.delete("/{dept_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_department(
    dept_id: int,
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    Delete a department (Admin only).
    """
    delete_department(session, dept_id)
