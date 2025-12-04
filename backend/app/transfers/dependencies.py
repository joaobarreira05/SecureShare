from fastapi import HTTPException, status
from typing import List, Dict, Any

def get_current_user() -> Dict[str, Any]:
    """
    Mock dependency to get the current authenticated user.
    In a real implementation, this would verify the JWT token.
    """
    return {
        "id": 1,
        "username": "test_user",
        "clearance": "TOP_SECRET",
        "departments": ["HR", "Finance"]
    }

def check_mls_write(user: Dict[str, Any], classification: str, departments: List[str]) -> bool:
    """
    Simulates the Bell-LaPadula *-Property check (No Write Down).
    Rule: User.clearance <= File.classification AND User.departments ⊇ File.departments.
    """
    # Mock clearance levels mapping
    clearance_levels = {
        "UNCLASSIFIED": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4
    }
    
    user_clearance_level = clearance_levels.get(user["clearance"], 0)
    file_classification_level = clearance_levels.get(classification, 0)
    
    # Check clearance (User <= File for write) - Wait, *-Property is No Write Down.
    # So a user with TOP_SECRET clearance cannot write to SECRET.
    # User.clearance <= File.classification
    if user_clearance_level > file_classification_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MLS violation: User clearance level is higher than file classification (No Write Down)."
        )

    # Check departments (User.departments ⊇ File.departments)
    user_departments = set(user["departments"])
    file_departments = set(departments)
    
    if not file_departments.issubset(user_departments):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MLS violation: User does not belong to all required departments."
        )

    return True

def check_mls_read(user: Dict[str, Any], classification: str, departments: List[str]) -> bool:
    """
    Simulates the Simple Security Property check (No Read Up).
    Rule: User.clearance >= File.classification AND User.departments ⊇ File.departments.
    """
    # Mock clearance levels mapping
    clearance_levels = {
        "UNCLASSIFIED": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4
    }
    
    user_clearance_level = clearance_levels.get(user["clearance"], 0)
    file_classification_level = clearance_levels.get(classification, 0)
    
    # Check clearance (User >= File for read)
    if user_clearance_level < file_classification_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MLS violation: User clearance level is lower than file classification (No Read Up)."
        )

    # Check departments (User.departments ⊇ File.departments)
    user_departments = set(user["departments"])
    file_departments = set(departments)
    
    if not file_departments.issubset(user_departments):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MLS violation: User does not belong to all required departments."
        )

    return True
