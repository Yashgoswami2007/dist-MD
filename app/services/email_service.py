"""Email service for sending OTP and other notifications."""
import logging
from typing import Optional

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


# Check if email is configured
EMAIL_CONFIGURED = bool(settings.MAIL_USERNAME and settings.MAIL_PASSWORD)

# Email configuration (only if credentials are provided)
conf = None
if EMAIL_CONFIGURED:
    try:
        conf = ConnectionConfig(
            MAIL_USERNAME=settings.MAIL_USERNAME,
            MAIL_PASSWORD=settings.MAIL_PASSWORD,
            MAIL_FROM=settings.MAIL_FROM or settings.MAIL_USERNAME,
            MAIL_PORT=settings.MAIL_PORT,
            MAIL_SERVER=settings.MAIL_SERVER,
            MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
            MAIL_STARTTLS=settings.MAIL_STARTTLS,
            MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True
        )
        logger.info("✅ Email service configured successfully")
    except Exception as e:
        logger.warning(f"⚠️ Email configuration failed: {e}")
        EMAIL_CONFIGURED = False
else:
    logger.warning("⚠️ Email service not configured (MAIL_USERNAME/MAIL_PASSWORD missing). OTPs will be logged to console.")


async def send_otp_email(email: str, otp_code: str, full_name: str) -> bool:
    """
    Send OTP verification email.
    
    Args:
        email: Recipient email address
        otp_code: 6-digit OTP code
        full_name: User's full name
    
    Returns:
        True if email sent successfully
    """
    if not EMAIL_CONFIGURED or conf is None:
        logger.warning("📧 Email service not configured. OTP will be shown in console.")
        logger.info(f"🔑 OTP for {email}: {otp_code}")  # Log for development
        return False
    
    try:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .otp-code {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #667eea;
                    text-align: center;
                    padding: 20px;
                    background: white;
                    border-radius: 8px;
                    letter-spacing: 8px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🌟 Welcome to MoodDoctor</h1>
                </div>
                <div class="content">
                    <h2>Hi {full_name}!</h2>
                    <p>Thank you for signing up for MoodDoctor, your AI-powered emotional wellness companion.</p>
                    <p>To complete your registration, please use the following verification code:</p>
                    
                    <div class="otp-code">{otp_code}</div>
                    
                    <p><strong>This code will expire in 10 minutes.</strong></p>
                    <p>If you didn't create an account with MoodDoctor, please ignore this email.</p>
                    
                    <div class="footer">
                        <p>© 2025 MoodDoctor. Your journey to emotional wellness.</p>
                        <p>This is an automated email, please do not reply.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        message = MessageSchema(
            subject="Your MoodDoctor Verification Code",
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )
        
        fm = FastMail(conf)
        await fm.send_message(message)
        
        logger.info(f"OTP email sent successfully to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending OTP email to {email}: {e}")
        logger.info(f"OTP for {email}: {otp_code}")  # Log for development
        return False


async def send_welcome_email(email: str, full_name: str) -> bool:
    """
    Send welcome email after successful verification.
    
    Args:
        email: User email address
        full_name: User's full name
    
    Returns:
        True if email sent successfully
    """
    if not EMAIL_CONFIGURED or conf is None:
        logger.info(f"📧 Welcome email skipped (email not configured) for {email}")
        return False
    
    try:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .cta-button {{
                    display: inline-block;
                    padding: 15px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Welcome to MoodDoctor!</h1>
                </div>
                <div class="content">
                    <h2>Hi {full_name}!</h2>
                    <p>Your email has been verified successfully. Welcome to MoodDoctor!</p>
                    <p>MoodDoctor is your AI-powered companion for emotional wellness. We're here to:</p>
                    <ul>
                        <li>🤝 Listen to your feelings without judgment</li>
                        <li>💡 Provide supportive guidance</li>
                        <li>🧘 Help you find calm during difficult moments</li>
                        <li>📈 Track your emotional journey</li>
                    </ul>
                    <p>Start your journey to better emotional health today!</p>
                    <div style="text-align: center;">
                        <a href="{settings.FRONTEND_URL}/chat" class="cta-button">Start Chatting</a>
                    </div>
                    <p><small>Remember: MoodDoctor is designed for emotional support, not medical diagnosis. If you're in crisis, please contact emergency services or a mental health professional.</small></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        message = MessageSchema(
            subject="Welcome to MoodDoctor! 🌟",
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )
        
        fm = FastMail(conf)
        await fm.send_message(message)
        
        logger.info(f"Welcome email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending welcome email to {email}: {e}")
        return False
