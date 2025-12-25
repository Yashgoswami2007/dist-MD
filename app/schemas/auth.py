"""Authentication API request/response schemas."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, validator


class RegisterRequest(BaseModel):
    """User registration request."""
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    full_name: str = Field(..., min_length=2, description="User's full name")
    
    @validator('password')
    def password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "password": "SecurePass123",
                "full_name": "John Doe"
            }
        }


class VerifyOTPRequest(BaseModel):
    """OTP verification request."""
    
    email: EmailStr = Field(..., description="User email address")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "otp_code": "123456"
            }
        }


class LoginRequest(BaseModel):
    """User login request."""
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "password": "SecurePass123"
            }
        }


class TokenResponse(BaseModel):
    """Authentication token response."""
    
    access_token: str = Field(... , description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    user: dict = Field(..., description="User information")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "user": {
                    "user_id": "user_abc123",
                    "email": "john@example.com",
                    "full_name": "John Doe",
                    "is_verified": True
                }
            }
        }


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    
    refresh_token: str = Field(..., description="JWT refresh token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class MessageResponse(BaseModel):
    """Generic message response."""
    
    message: str = Field(..., description="Response message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation completed successfully"
            }
        }
