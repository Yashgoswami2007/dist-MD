"""User database service for authentication operations."""
import logging
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import mongodb
from app.db.user_models import OTPDocument, UserDocument

logger = logging.getLogger(__name__)


class UserService:
    """Service layer for user authentication database operations."""

    @staticmethod
    async def create_user(
        user_id: str,
        email: str,
        hashed_password: str,
        full_name: str,
        oauth_provider: Optional[str] = None,
        oauth_id: Optional[str] = None,
        is_verified: bool = False
    ) -> UserDocument:
        """
        Create a new user in the database.
        
        Args:
            user_id: Unique user identifier
            email: User email address
            hashed_password: Bcrypt hashed password
            full_name: User's full name
            oauth_provider: OAuth provider (e.g., 'google') or None
            oauth_id: OAuth provider user ID
            is_verified: Email verification status
        
        Returns:
            Created user document
        """
        try:
            db = mongodb.get_db()
            collection = db.users
            
            user = UserDocument(
                user_id=user_id,
                email=email,
                hashed_password=hashed_password,
                full_name=full_name,
                is_verified=is_verified,
                is_active=True,
                oauth_provider=oauth_provider,
                oauth_id=oauth_id,
                created_at=datetime.now(),
                last_login=None
            )
            
            await collection.insert_one(user.model_dump())
            logger.info(f"Created user {user_id} with email {email}")
            
            return user
            
        except Exception as e:
            logger.error(f"Error creating user {email}: {e}")
            raise

    @staticmethod
    async def get_user_by_email(email: str) -> Optional[dict]:
        """
        Get user by email address.
        
        Args:
            email: User email address
        
        Returns:
            User document dict or None if not found
        """
        try:
            db = mongodb.get_db()
            collection = db.users
            
            user = await collection.find_one({"email": email})
            
            if user:
                user.pop("_id", None)
                logger.debug(f"Found user with email {email}")
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None

    @staticmethod
    async def get_user_by_id(user_id: str) -> Optional[dict]:
        """
        Get user by user_id.
        
        Args:
            user_id: User identifier
        
        Returns:
            User document dict or None if not found
        """
        try:
            db = mongodb.get_db()
            collection = db.users
            
            user = await collection.find_one({"user_id": user_id})
            
            if user:
                user.pop("_id", None)
                logger.debug(f"Found user {user_id}")
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {e}")
            return None

    @staticmethod
    async def get_user_by_oauth(provider: str, oauth_id: str) -> Optional[dict]:
        """
        Get user by OAuth provider and ID.
        
        Args:
            provider: OAuth provider name (e.g., 'google')
            oauth_id: OAuth provider user ID
        
        Returns:
            User document dict or None if not found
        """
        try:
            db = mongodb.get_db()
            collection = db.users
            
            user = await collection.find_one({
                "oauth_provider": provider,
                "oauth_id": oauth_id
            })
            
            if user:
                user.pop("_id", None)
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting user by OAuth {provider}/{oauth_id}: {e}")
            return None

    @staticmethod
    async def update_user(user_id: str, update_data: dict) -> bool:
        """
        Update user fields.
        
        Args:
            user_id: User identifier
            update_data: Dict of fields to update
        
        Returns:
            True if updated successfully
        """
        try:
            db = mongodb.get_db()
            collection = db.users
            
            result = await collection.update_one(
                {"user_id": user_id},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                logger.debug(f"Updated user {user_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False

    @staticmethod
    async def verify_user_email(email: str) -> bool:
        """
        Mark user email as verified.
        
        Args:
            email: User email address
        
        Returns:
            True if verified successfully
        """
        user = await UserService.get_user_by_email(email)
        if not user:
            return False
        
        return await UserService.update_user(
            user["user_id"],
            {"is_verified": True}
        )

    @staticmethod
    async def update_last_login(user_id: str) -> bool:
        """
        Update user's last login timestamp.
        
        Args:
            user_id: User identifier
        
        Returns:
            True if updated successfully
        """
        return await UserService.update_user(
            user_id,
            {"last_login": datetime.now()}
        )

    # OTP Operations

    @staticmethod
    async def create_otp(email: str, otp_code: str, expire_minutes: int = 10) -> bool:
        """
        Create and store OTP code.
        
        Args:
            email: User email address
            otp_code: 6-digit OTP code
            expire_minutes: OTP validity in minutes
        
        Returns:
            True if created successfully
        """
        try:
            db = mongodb.get_db()
            collection = db.otps
            
            # Delete any existing OTP for this email
            await collection.delete_many({"email": email})
            
            otp = OTPDocument(
                email=email,
                otp_code=otp_code,
                expires_at=datetime.now() + timedelta(minutes=expire_minutes),
                created_at=datetime.now()
            )
            
            await collection.insert_one(otp.model_dump())
            logger.info(f"Created OTP for {email}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating OTP for {email}: {e}")
            return False

    @staticmethod
    async def verify_otp(email: str, otp_code: str) -> bool:
        """
        Verify OTP code.
        
        Args:
            email: User email address
            otp_code: 6-digit OTP code to verify
        
        Returns:
            True if OTP is valid and not expired
        """
        try:
            db = mongodb.get_db()
            collection = db.otps
            
            otp = await collection.find_one({
                "email": email,
                "otp_code": otp_code
            })
            
            if not otp:
                logger.warning(f"Invalid OTP for {email}")
                return False
            
            # Check if expired
            if datetime.now() > otp["expires_at"]:
                logger.warning(f"Expired OTP for {email}")
                await collection.delete_one({"email": email})
                return False
            
            # Valid OTP - delete it (one-time use)
            await collection.delete_one({"email": email})
            logger.info(f"Valid OTP verified for {email}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying OTP for {email}: {e}")
            return False

    @staticmethod
    async def delete_expired_otps():
        """Delete all expired OTP codes."""
        try:
            db = mongodb.get_db()
            collection = db.otps
            
            result = await collection.delete_many({
                "expires_at": {"$lt": datetime.now()}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} expired OTPs")
            
        except Exception as e:
            logger.error(f"Error deleting expired OTPs: {e}")


# Singleton instance
user_service = UserService()
