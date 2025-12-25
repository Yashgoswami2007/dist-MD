"""MongoDB database connection and lifecycle management."""
import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ConnectionFailure

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class MongoDB:
    """MongoDB connection manager with singleton pattern."""
    
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None

    @classmethod
    async def connect(cls):
        """Initialize MongoDB connection."""
        if cls.client is not None:
            logger.warning("MongoDB client already exists. Skipping connection.")
            return

        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL[:30]}...")
            
            # Create async MongoDB client
            cls.client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
            )
            
            # Get database
            cls.db = cls.client[settings.MONGODB_DB_NAME]
            
            # Test connection
            await cls.client.admin.command('ping')
            logger.info(f"✅ Successfully connected to MongoDB database: {settings.MONGODB_DB_NAME}")
            
            # Create indexes
            await cls._create_indexes()
            
        except ConnectionFailure as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error connecting to MongoDB: {e}")
            raise

    @classmethod
    async def _create_indexes(cls):
        """Create database indexes for optimal performance."""
        if cls.db is None:
            return
        
        try:
            conversations = cls.db.conversations
            
            # Index on conversation_id (unique)
            await conversations.create_index("conversation_id", unique=True)
            
            # Index on user_id for user-specific queries
            await conversations.create_index("user_id")
            
            # Compound index on (user_id, updated_at) for sorting user's conversations
            await conversations.create_index([("user_id", 1), ("updated_at", -1)])
            
            logger.info("✅ Database indexes created successfully")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to create indexes: {e}")

    @classmethod
    async def close(cls):
        """Close MongoDB connection."""
        if cls.client is None:
            logger.warning("MongoDB client doesn't exist. Nothing to close.")
            return

        try:
            cls.client.close()
            cls.client = None
            cls.db = None
            logger.info("✅ MongoDB connection closed")
        except Exception as e:
            logger.error(f"❌ Error closing MongoDB connection: {e}")

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        """Get database instance."""
        if cls.db is None:
            raise RuntimeError("MongoDB not connected. Call MongoDB.connect() first.")
        return cls.db

    @classmethod
    async def health_check(cls) -> dict:
        """Check MongoDB health status."""
        if cls.client is None or cls.db is None:
            return {"status": "disconnected", "database": None}
        
        try:
            await cls.client.admin.command('ping')
            return {
                "status": "connected",
                "database": settings.MONGODB_DB_NAME,
            }
        except Exception as e:
            return {
                "status": "error",
                "database": settings.MONGODB_DB_NAME,
                "error": str(e),
            }


# Singleton instance
mongodb = MongoDB()
