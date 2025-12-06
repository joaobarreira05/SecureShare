from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional
from ..models.User import User
from ..models.Role import Role
from ..models.Transfer import SecurityLevel

# Clearance levels mapping
CLEARANCE_LEVELS = {
    SecurityLevel.UNCLASSIFIED: 1,
    SecurityLevel.CONFIDENTIAL: 2,
    SecurityLevel.SECRET: 3,
    SecurityLevel.TOP_SECRET: 4
}

def check_mls_write(
    user: User, 
    classification: SecurityLevel, 
    departments: List[str],
    mls_payload: Optional[dict] = None,
    justification: Optional[str] = None,
    is_trusted_officer: bool = False
) -> bool:
    """
    Enforces the Bell-LaPadula *-Property (No Write Down).
    Rule: User.clearance <= File.classification AND User.departments ⊇ File.departments.
    
    If check fails, allows bypass if User is TRUSTED_OFFICER and provides justification.
    """
    
    # 1. Check if MLS Token is present
    if not mls_payload:
        # If no MLS token, we can't check clearance. 
        # Unless we assume default clearance? No, requirements say token is mandatory.
        # But we check for Trusted Officer bypass below.
        pass
    else:
        # Extract clearance and departments from token
        user_clearance_str = mls_payload.get("clearance")
        user_departments = set(mls_payload.get("departments", []))
        
        user_clearance_level = CLEARANCE_LEVELS.get(user_clearance_str, 0)
        file_classification_level = CLEARANCE_LEVELS.get(classification, 0)
        
        # Check clearance (User <= File for write)
        # *-Property: A subject at a high level cannot write to a low level.
        # So User Level must be <= Object Level.
        # Example: Top Secret User cannot write to Secret File.
        clearance_ok = user_clearance_level <= file_classification_level
        
        # Check departments (*-Property: User.departments ⊆ File.departments)
        # User can only write to files that have ALL of their departments.
        file_departments = set(departments)
        departments_ok = user_departments.issubset(file_departments)
        
        if clearance_ok and departments_ok:
            return True

    # 2. Trusted Officer Bypass
    if is_trusted_officer:
        if justification and len(justification.strip()) > 0:
            # Log this bypass (TODO: Implement Audit Log)
            print(f"AUDIT: Trusted Officer {user.username} bypassed MLS Write check. Justification: {justification}")
            return True
        else:
             raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Trusted Officer bypass requires a valid justification."
            )

    # 3. Fail with detailed requirements
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "message": "MLS violation: Write access denied (No Write Down).",
            "required_max_clearance": classification,
            "required_departments": departments
        }
    )

def check_mls_read(
    user: User, 
    classification: SecurityLevel, 
    departments: List[str],
    mls_payload: Optional[dict] = None,
    justification: Optional[str] = None,
    is_trusted_officer: bool = False
) -> bool:
    """
    Enforces the Simple Security Property (No Read Up).
    Rule: User.clearance >= File.classification AND User.departments ⊇ File.departments.
    
    If check fails, allows bypass if User is TRUSTED_OFFICER and provides justification.
    """
    
    if mls_payload:
        user_clearance_str = mls_payload.get("clearance")
        user_departments = set(mls_payload.get("departments", []))
        
        user_clearance_level = CLEARANCE_LEVELS.get(user_clearance_str, 0)
        file_classification_level = CLEARANCE_LEVELS.get(classification, 0)
        
        # Check clearance (User >= File for read)
        # Simple Security Property: Subject can read Object only if Subject Level >= Object Level.
        clearance_ok = user_clearance_level >= file_classification_level
        
        # Check departments (User.departments ⊇ File.departments)
        file_departments = set(departments)
        departments_ok = file_departments.issubset(user_departments)
        
        if clearance_ok and departments_ok:
            return True

    # Trusted Officer Bypass
    if is_trusted_officer:
        if justification and len(justification.strip()) > 0:
            # Log this bypass (TODO: Implement Audit Log)
            print(f"AUDIT: Trusted Officer {user.username} bypassed MLS Read check. Justification: {justification}")
            return True
        else:
             raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Trusted Officer bypass requires a valid justification."
            )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "message": "MLS violation: Read access denied (No Read Up).",
            "required_min_clearance": classification,
            "required_departments": departments
        }
    )
