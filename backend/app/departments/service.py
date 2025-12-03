from fastapi import HTTPException, status
from sqlmodel import Session, select
from ..models.Department import Department, DepartmentCreate

def create_department(session: Session, department: DepartmentCreate) -> Department:
    statement = select(Department).where(Department.name == department.name)
    existing_dept = session.exec(statement).first()
    if existing_dept:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Department with this name already exists"
        )
    
    db_dept = Department.model_validate(department)
    session.add(db_dept)
    session.commit()
    session.refresh(db_dept)
    return db_dept

def get_all_departments(session: Session) -> list[Department]:
    statement = select(Department)
    return session.exec(statement).all()

def delete_department(session: Session, dept_id: int):
    dept = session.get(Department, dept_id)
    if not dept:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Department not found"
        )
    session.delete(dept)
    session.commit()
