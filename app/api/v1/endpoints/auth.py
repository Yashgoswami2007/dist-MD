import logging
import random
import string
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from google.oauth2 import id_token
from google.auth.transport import requests
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from app.core.config import get_settings
from app.db.user_models import UserResponse
from app.db.user_service import user_service
from app.services.email_service import send_otp_email, send_welcome_email
from app.services.oauth import oauth

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)


# Security configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    
    user = await user_service.get_user_by_email(email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_user_optional(token: str = Depends(oauth2_scheme)) -> dict | None:
    """Get current user if authenticated, else None."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("email")
        if email:
            return await user_service.get_user_by_email(email)
    except Exception:
        pass
    return None


# Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user_info: UserResponse

class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str

# Helpers
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=30)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

# Endpoints

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, background_tasks: BackgroundTasks):
    """Register a new user and send OTP."""
    # Check existing
    if await user_service.get_user_by_email(user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    hashed_password = get_password_hash(user_in.password)
    
    await user_service.create_user(
        user_id=user_id,
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=user_in.full_name
    )
    
    # Generate and send OTP
    otp_code = generate_otp()
    await user_service.create_otp(user_in.email, otp_code)
    
    # Send email in background
    background_tasks.add_task(send_otp_email, user_in.email, otp_code, user_in.full_name)
    
    return {"message": "User registered successfully. Please verify your email with the OTP sent."}

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login with email and password."""
    user = await user_service.get_user_by_email(form_data.username)
    
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.get("is_verified"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
        )
        
    # Update last login
    await user_service.update_last_login(user["user_id"])
    
    # Create tokens
    access_token = create_access_token(data={"sub": user["container_id"] if "container_id" in user else user["user_id"], "email": user["email"]})
    refresh_token = create_refresh_token(data={"sub": user["user_id"]})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_info": UserResponse(**user)
    }

@router.post("/verify-otp")
async def verify_otp(otp_in: OTPVerify, background_tasks: BackgroundTasks):
    """Verify email with OTP code."""
    is_valid = await user_service.verify_otp(otp_in.email, otp_in.otp_code)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )
        
    # Verify user
    await user_service.verify_user_email(otp_in.email)
    
    # Get user info
    user = await user_service.get_user_by_email(otp_in.email)
    
    # Send welcome email
    if user:
        background_tasks.add_task(send_welcome_email, user["email"], user["full_name"])
        
        # Auto-login token
        access_token = create_access_token(data={"sub": user["user_id"], "email": user["email"]})
        refresh_token = create_refresh_token(data={"sub": user["user_id"]})
        
        return {
            "message": "Email verified successfully",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_info": UserResponse(**user)
        }
        
    return {"message": "Email verified successfully"}

# Google OAuth Endpoints

@router.get("/google/login")
async def google_login(request: Request):
    """Redirect to Google OAuth login."""
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/google/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info:
            # Fallback if userinfo not in token
            user_info = await oauth.google.userinfo(token=token)
            
        email = user_info.get('email')
        full_name = user_info.get('name')
        google_id = user_info.get('sub') # Google unique ID
        
        if not email:
            raise HTTPException(status_code=400, detail="Could not retrieve email from Google")
            
        # Check if user exists
        user = await user_service.get_user_by_email(email)
        
        if not user:
            # Create new user
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            await user_service.create_user(
                user_id=user_id,
                email=email,
                hashed_password="oauth_user", # Placeholder
                full_name=full_name,
                oauth_provider="google",
                oauth_id=google_id,
                is_verified=True # Google emails are verified
            )
            user = await user_service.get_user_by_email(email)
        else:
            # Update existing user with OAuth info if missing
            if not user.get("oauth_id"):
                await user_service.update_user(user["user_id"], {
                    "oauth_provider": "google",
                    "oauth_id": google_id,
                    "is_verified": True
                })
        
        # Generate tokens
        access_token = create_access_token(data={"sub": user["user_id"], "email": email})
        refresh_token = create_refresh_token(data={"sub": user["user_id"]})
        
        # Redirect to frontend with tokens in URL fragment
        # Note: In production, consider a secure cookie or postMessage
        frontend_redirect = f"{settings.FRONTEND_URL}/auth/callback#access_token={access_token}&refresh_token={refresh_token}&full_name={full_name}"
        
        return RedirectResponse(url=frontend_redirect)
        
    except Exception as e:
        logger.error(f"Google OAuth Error: {e}")
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/auth?error=oauth_failed")
