import json
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Optional

import gspread
from google.oauth2.service_account import Credentials

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

class GoogleSheetsService:
    def __init__(self):
        self.client = None
        self.sheet = None
        self.chat_worksheet = None
        self.mood_worksheet = None
        self.is_connected = False
        self.use_api_key = False
        
    async def connect(self):
        """Connect to Google Sheets using service account or API Key."""
        if self.is_connected:
            return

        # Priority 1: Service Account
        if settings.GOOGLE_SHEETS_CREDENTIALS:
            try:
                # Parse credentials from string or file
                try:
                    creds_dict = json.loads(settings.GOOGLE_SHEETS_CREDENTIALS)
                except json.JSONDecodeError:
                    # Assume it's a file path if not JSON
                    with open(settings.GOOGLE_SHEETS_CREDENTIALS) as f:
                        creds_dict = json.load(f)
                
                creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
                self.client = gspread.authorize(creds)
                
                # Open or Create Spreadsheet
                try:
                    self.sheet = self.client.open("MoodDoctor Data")
                except gspread.SpreadsheetNotFound:
                    self.sheet = self.client.create("MoodDoctor Data")
                    # Share with admin email if available in credentials
                    if 'client_email' in creds_dict:
                        logger.info(f"Created new sheet 'MoodDoctor Data'. Created by {creds_dict['client_email']}")

                # Setup Worksheets
                self.chat_worksheet = self._get_or_create_worksheet("Chat Logs", ["User ID", "Role", "Content", "Mood", "Timestamp"])
                self.mood_worksheet = self._get_or_create_worksheet("Mood Stats", ["User ID", "Date", "Dominant Mood", "Energy", "Score", "Timestamp"])
                
                self.is_connected = True
                logger.info("✅ Connected to Google Sheets (Service Account)")
                return
                
            except Exception as e:
                logger.error(f"❌ Failed to connect to Google Sheets via Service Account: {e}")
                # Fallthrough to API Key if available

        # Priority 2: API Key + Sheet ID
        if settings.GOOGLE_SHEETS_API_KEY and settings.GOOGLE_SHEETS_ID:
            self.use_api_key = True
            self.is_connected = True
            logger.info("⚠️ Using Google Sheets API Key. Ensure Sheet ID is correct and 'Anyone with link can editor' is set if writing fails.")
            return

        logger.warning("⚠️ Google Sheets credentials or API Key not found. Sheets logging disabled.")

    def _get_or_create_worksheet(self, title: str, headers: list):
        """Helper to get or create a worksheet with headers (Service Account only)."""
        if self.use_api_key: return None
        try:
            ws = self.sheet.worksheet(title)
        except gspread.WorksheetNotFound:
            ws = self.sheet.add_worksheet(title, rows=1000, cols=10)
            ws.append_row(headers)
        return ws

    async def _append_via_api(self, range_name: str, values: list):
        """Append row using REST API (for API Key usage)."""
        if not settings.GOOGLE_SHEETS_ID: return
        
        url = f"https://sheets.googleapis.com/v4/spreadsheets/{settings.GOOGLE_SHEETS_ID}/values/{range_name}:append"
        params = {
            "key": settings.GOOGLE_SHEETS_API_KEY,
            "valueInputOption": "USER_ENTERED",
            "insertDataOption": "INSERT_ROWS"
        }
        body = {
            "range": range_name,
            "majorDimension": "ROWS",
            "values": [values]
        }
        
        try:
            # Note: This often fails for API Keys without OAuth, but implemented as requested.
            resp = requests.post(url, params=params, json=body)
            if not resp.ok:
                logger.error(f"Sheets API Error ({resp.status_code}): {resp.text}")
        except Exception as e:
             logger.error(f"Sheets REST Request Failed: {e}")

    async def log_chat_message(self, user_id: str, role: str, content: str, mood: Optional[str] = None):
        """Log a chat message to Sheets."""
        if not self.is_connected:
            await self.connect()
            if not self.is_connected: return

        try:
            timestamp = datetime.now().isoformat()
            row = [user_id, role, content, mood or "", timestamp]
            
            if self.use_api_key:
                await self._append_via_api("Chat Logs!A:E", row)
            else:
                self.chat_worksheet.append_row(row)
                
        except Exception as e:
            logger.error(f"Error logging to Sheets: {e}")

    async def log_mood_stat(self, user_id: str, mood_data: Dict[str, Any]):
        """Log mood statistics."""
        if not self.is_connected:
            await self.connect()
            if not self.is_connected: return
            
        try:
            timestamp = datetime.now().isoformat()
            row = [
                user_id, 
                timestamp.split("T")[0], # Date
                mood_data.get('dominant_mood', ''),
                mood_data.get('energy_level', ''),
                mood_data.get('score', 0),
                timestamp
            ]
            
            if self.use_api_key:
                await self._append_via_api("Mood Stats!A:F", row)
            else:
                self.mood_worksheet.append_row(row)
                
        except Exception as e:
            logger.error(f"Error logging mood stat: {e}")


# Singleton
sheets_service = GoogleSheetsService()
