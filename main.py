# 1. Import necessary libraries
import os
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
# NEW: Import the CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from openai import OpenAI

# Firebase Admin SDK for backend database operations
import firebase_admin
from firebase_admin import credentials, firestore

# --- Application Setup ---
app = FastAPI()
load_dotenv()

# --- NEW: Add CORS Middleware ---
# This is the crucial part that fixes the error.
# It allows your frontend to communicate with your backend.
origins = [
    "null",  # Allow requests from local files (like your index.html)
    "http://localhost",
    "http://localhost:8080", # Add other origins if needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods (GET, POST, etc.)
    allow_headers=["*"], # Allows all headers
)

# --- Firebase Admin SDK Initialization ---
try:
    if not firebase_admin._apps:
        cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH")
        if not cred_path or not os.path.exists(cred_path):
            raise ValueError(f"Service account key file not found at path: {cred_path}.")
        
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"FATAL ERROR: Firebase Admin SDK initialization failed: {e}")
    exit()

db = firestore.client()

# --- Security and Authentication Setup ---
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Pydantic Models (Data Schemas) ---
class UserAuth(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)

class QuizData(BaseModel):
    skills: str
    interests: str
    experience: str

# --- Helper Functions (No changes here) ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except jwt.PyJWTError:
        raise credentials_exception

# --- API Endpoints (No changes here) ---
@app.post("/register")
async def register(user: UserAuth):
    users_ref = db.collection('users').document(user.username)
    if users_ref.get().exists:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    user_data = {
        "username": user.username,
        "hashed_password": hashed_password,
        "quiz_completed": False,
        "created_at": datetime.utcnow()
    }
    users_ref.set(user_data)
    return {"message": "User registered successfully"}

@app.post("/token")
async def login(form_data: UserAuth):
    users_ref = db.collection('users').document(form_data.username)
    user_doc = users_ref.get()

    if not user_doc.exists or not verify_password(form_data.password, user_doc.to_dict()['hashed_password']):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: str = Depends(get_current_user)):
    user_doc = db.collection('users').document(current_user).get()
    if user_doc.exists:
        return user_doc.to_dict()
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/submit-quiz")
async def submit_quiz(quiz_data: QuizData, current_user: str = Depends(get_current_user)):
    prompt = f"""
    Act as an expert career navigator AI. A student has provided the following information:
    - Current Skills: {quiz_data.skills}
    - Interests: {quiz_data.interests}
    - Experience Level: {quiz_data.experience}
    Based on this profile, suggest 3 diverse and actionable career paths. For each path, provide a brief, one-paragraph summary of why it's a good fit. Then, select the TOP recommendation and provide a simple, 3-step starting plan.
    Format the entire output in clean Markdown.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert career navigator AI."},
                {"role": "user", "content": prompt}
            ]
        )
        ai_recommendation = response.choices[0].message.content
        user_ref = db.collection('users').document(current_user)
        user_ref.update({
            "quiz_data": quiz_data.dict(),
            "ai_recommendation": ai_recommendation,
            "quiz_completed": True,
            "last_updated": datetime.utcnow()
        })
        return {"message": "Quiz submitted successfully!", "recommendation": ai_recommendation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred with the AI model: {str(e)}")

