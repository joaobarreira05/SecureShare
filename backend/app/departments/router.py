from fastapi import APIRouter, Depends, status
import http
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
    action = f"POST /departments {status.HTTP_201_CREATED} {http.HTTPStatus(status.HTTP_201_CREATED).phrase}"
    log_event(session, current_admin.id, action, "Department created successfully")
    return create_department(session, department)

@router.get("", response_model=list[DepartmentResponse])
async def read_departments(
    session: Session = Depends(get_session),
    current_admin: User = Depends(get_current_active_admin)
):
    """
    List all departments (Admin only).
    """
    action = f"POST /departments {status.HTTP_200_OK} {http.HTTPStatus(status.HTTP_200_OK).phrase}"
    log_event(session, current_admin.id, action, "Departments listed successfully")
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
    action = f"POST /departments/{dept_id} {status.HTTP_204_NO_CONTENT} {http.HTTPStatus(status.HTTP_204_NO_CONTENT).phrase}"
    log_event(session, current_admin.id, action, "Department deleted successfully")
    delete_department(session, dept_id)
