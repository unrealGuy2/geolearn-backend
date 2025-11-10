from pydantic import BaseModel, EmailStr
from typing import Optional

# --- User Schemas ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str
    level: Optional[str] = None

class User(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    level: Optional[str] = None # <-- FIX IS HERE

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Course Schemas ---
class CourseBase(BaseModel):
    course_code: str
    course_title: str

class CourseCreate(CourseBase):
    pass

class Course(CourseBase):
    id: str

    class Config:
        from_attributes = True

# --- Material Schemas ---
class Material(BaseModel):
    id: str
    title: str
    material_type: str
    file_url: str
    course_id: str
    status: str
    uploaded_by: str

    class Config:
        from_attributes = True

class MaterialPublic(BaseModel):
    id: str
    title: str
    material_type: str
    file_url: str
    status: str
    courses: Optional[CourseBase] = None

    class Config:
        from_attributes = True