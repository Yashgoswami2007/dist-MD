"""Google OAuth integration."""
import logging
from typing import Optional

import httpx
from authlib.integrations.starlette_client import OAuth

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# Initialize OAuth
oauth = OAuth()

# Register Google OAuth provider
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


async def get_google_user_info(access_token: str) -> Optional[dict]:
    """
    Fetch user information from Google using access token.
    
    Args:
        access_token: Google OAuth access token
    
    Returns:
        User info dict with email, name, etc.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            response.raise_for_status()
            user_info = response.json()
            logger.info(f"Fetched Google user info for {user_info.get('email')}")
            return user_info
    except Exception as e:
        logger.error(f"Error fetching Google user info: {e}")
        return None
