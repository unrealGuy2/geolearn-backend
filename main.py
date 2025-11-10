import os
import datetime
from fastapi import FastAPI, HTTPException, Depends, Form, File, UploadFile
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from supabase import create_client, Client
from schemas import (
    UserCreate, Token, User, CourseCreate, Course, Material, MaterialPublic
)
from typing import Annotated, List, Optional
from pydantic import BaseModel, EmailStr

load_dotenv()

app = FastAPI()

# --- CORS Configuration ---
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://geolearn-frontend.vercel.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- END CORS Configuration ---


url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_SERVICE_KEY")
supabase: Client = create_client(url, key)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- Schemas (Moved from schemas.py for simplicity in one file) ---

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
    level: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class CourseBase(BaseModel):
    course_code: str
    course_title: str

class CourseCreate(CourseBase):
    pass

class Course(CourseBase):
    id: str
    class Config:
        from_attributes = True

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

# --- Security Dependencies ---

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        user_response = supabase.auth.get_user(token)
        user_data = user_response.user
        
        profile_response = supabase.table("users").select("*").eq("id", user_data.id).execute()
        
        if not profile_response.data:
            raise HTTPException(status_code=404, detail="User profile not found")
        
        return User.model_validate(profile_response.data[0]) 
    
    except Exception as e:
        print(f"Auth Error: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Forbidden: Not an admin")
    return current_user

# --- Public Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Hello! Welcome to the Geology Department App API."}

@app.post("/signup")
def create_user(user: UserCreate):
    try:
        auth_response = supabase.auth.sign_up({
            "email": user.email,
            "password": user.password
        })
        
        new_user_id = auth_response.user.id

        user_data_to_insert = {
            "id": new_user_id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "level": user.level
        }
        
        insert_response = supabase.table("users").insert(user_data_to_insert).execute()
        
        if insert_response.data:
            return {"message": "User created successfully", "user_id": new_user_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to save user public data")

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login", response_model=Token)
def login_user(username: Annotated[EmailStr, Form()], password: Annotated[str, Form()]):
    try:
        response = supabase.auth.sign_in_with_password({
            "email": username,
            "password": password
        })
        
        access_token = response.session.access_token
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.get("/materials", response_model=List[MaterialPublic])
def get_all_materials():
    try:
        response = supabase.table("materials").select(
            """
            id,
            title,
            material_type,
            file_url,
            status,
            courses (
                course_code,
                course_title
            )
            """
        ).eq("status", "approved").execute()
        
        return response.data
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/courses", response_model=List[Course])
def get_all_courses(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("courses").select("*").order("course_code").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Protected Endpoints ---

@app.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- Admin-Only Endpoints ---

@app.get("/admin/metrics")
def get_admin_metrics(admin_user: User = Depends(get_admin_user)):
    try:
        user_count_response = supabase.table("users").select("id", count="exact").execute()
        total_users = user_count_response.count

        material_count_response = supabase.table("materials").select("id", count="exact").execute()
        total_materials = material_count_response.count

        course_count_response = supabase.table("courses").select("id", count="exact").execute()
        total_courses = course_count_response.count

        return {
            "total_users": total_users,
            "total_materials": total_materials,
            "total_courses": total_courses
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch metrics: {str(e)}")


@app.post("/courses", response_model=Course)
def create_course(
    course: CourseCreate, 
    admin_user: User = Depends(get_admin_user)
):
    try:
        response = supabase.table("courses").insert(course.model_dump()).execute()
        return response.data[0]
    except Exception as e:
        if "unique constraint" in str(e):
            raise HTTPException(status_code=400, detail="Course code already exists")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/materials/upload", response_model=Material)
def upload_material(
    title: str = Form(...),
    material_type: str = Form(...),
    course_id: str = Form(...),
    file: UploadFile = File(...),
    admin_user: User = Depends(get_admin_user)
):
    try:
        timestamp = datetime.datetime.now().isoformat().replace(":", "-")
        file_path = f"course_{course_id}/{timestamp}_{file.filename}"

        file_content = file.file.read()

        supabase.storage.from_("materials").upload(
            path=file_path,
            file=file_content,
            file_options={"content-type": file.content_type}
        )

        file_url = supabase.storage.from_("materials").get_public_url(file_path)

        material_data = {
            "title": title,
            "material_type": material_type,
            "file_url": file_url,
            "course_id": course_id,
            "uploaded_by": admin_user.id,
            "status": "approved"
        }

        db_response = supabase.table("materials").insert(material_data).execute()
        
        return db_response.data[0]

    except Exception as e:
        if "foreign key constraint" in str(e):
            raise HTTPException(status_code=404, detail="Invalid course_id. Course does not exist.")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@app.get("/admin/users", response_model=List[User])
def get_all_users(admin_user: User = Depends(get_admin_user)):
    try:
        response = supabase.table("users").select("*").order("full_name").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- NEW ENDPOINT TO PROMOTE A USER ---
@app.post("/admin/users/{user_id}/promote", response_model=User)
def promote_user(user_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        # Update the user's role to 'admin'
        response = supabase.table("users").update({"role": "admin"}).eq("id", user_id).select().execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="User not found")
        
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))