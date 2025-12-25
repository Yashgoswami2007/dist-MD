from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.v1.endpoints import mood, stream, train
from app.core.logging import configure_logging, get_logger
from app.core.database import mongodb


def create_app() -> FastAPI:
    configure_logging()
    logger = get_logger("mooddoctor.app")

    app = FastAPI(
        title="MoodDoctor Backend",
        version="0.1.0",
        description="Multimodal mood detection and supportive response API.",
    )

    # CORS middleware for frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8080",  # Vite dev server
            "http://localhost:3000",  # Alternative port
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Session Middleware for OAuth
    from starlette.middleware.sessions import SessionMiddleware
    from app.core.config import get_settings
    settings = get_settings()
    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

    # MongoDB lifecycle events
    @app.on_event("startup")
    async def startup_db_client():
        """Initialize MongoDB connection on startup."""
        try:
            await mongodb.connect()
            logger.info("🚀 MoodDoctor API started successfully with MongoDB connection")
        except Exception as e:
            logger.error(f"❌ Failed to connect to MongoDB on startup: {e}")
            logger.warning("⚠️ API will run but database operations may fail")

    @app.on_event("shutdown")
    async def shutdown_db_client():
        """Close MongoDB connection on shutdown."""
        await mongodb.close()
        logger.info("👋 MoodDoctor API shutting down")

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint with database status."""
        db_health = await mongodb.health_check()
        return JSONResponse(content={
            "status": "running",
            "database": db_health
        })

    # Main landing page
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Main landing page with MOOD DOCTOR title and buttons."""
        return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MoodDoctor AI</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            max-width: 600px;
            padding: 40px;
        }
        h1 {
            font-size: 48px;
            font-weight: 700;
            color: #333;
            margin-bottom: 20px;
            letter-spacing: -1px;
        }
        .subtitle {
            font-size: 18px;
            color: #666;
            margin-bottom: 50px;
            line-height: 1.6;
        }
        .buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .btn {
            padding: 16px 40px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.2s;
        }
        .btn:hover {
            border-color: #999;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MOOD DOCTOR</h1>
        <p class="subtitle">
            An emotionally intelligent AI that analyzes your mood from text, facial expressions, and voice, 
            then provides supportive, safe responses.
        </p>
        <div class="buttons">
            <a href="/docs" class="btn">📚 API Docs</a>
            <a href="/chat" class="btn">💬 Chat Now</a>
            <a href="/train" class="btn">🛠️ TRAIN MODEL</a>
        </div>
    </div>
</body>
</html>
        """)

    # Chat page with full features
    @app.get("/chat", response_class=HTMLResponse)
    async def chat_page():
        """Full chat interface with text, image upload, and voice recording."""
        return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MoodDoctor AI - Chat</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: white;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: white;
            border-bottom: 1px solid #ddd;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 24px;
            font-weight: 600;
            color: #333;
        }
        .back-btn {
            padding: 8px 16px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
            cursor: pointer;
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            overflow: hidden;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: white;
        }
        .message {
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
        }
        .message.user {
            align-items: flex-end;
        }
        .message.assistant {
            align-items: flex-start;
        }
        .message-bubble {
            max-width: 70%;
            padding: 12px 18px;
            border-radius: 5px;
            word-wrap: break-word;
            border: 1px solid #e0e0e0;
        }
        .message.user .message-bubble {
            background: #f5f5f5;
            color: #333;
        }
        .message.assistant .message-bubble {
            background: #f5f5f5;
            color: #333;
        }
        .message-image {
            max-width: 200px;
            border-radius: 5px;
            margin-top: 5px;
        }
        .input-area {
            padding: 20px;
            background: white;
            border-top: 1px solid #ddd;
        }
        .file-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }
        .file-btn {
            padding: 10px 16px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .file-btn:hover {
            border-color: #999;
        }
        .file-btn input[type="file"] {
            display: none;
        }
        .file-preview {
            margin-bottom: 10px;
            padding: 8px;
            background: #f5f5f5;
            border-radius: 5px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .file-preview img {
            max-width: 50px;
            max-height: 50px;
            border-radius: 5px;
        }
        .file-preview button {
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 18px;
        }
        .input-group {
            display: flex;
            gap: 10px;
        }
        #messageInput {
            flex: 1;
            padding: 12px 18px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            outline: none;
        }
        #messageInput:focus {
            border-color: #999;
        }
        #sendButton {
            padding: 12px 24px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-weight: 600;
            cursor: pointer;
        }
        #sendButton:hover {
            border-color: #999;
        }
        #sendButton:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .recording {
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>💬 MoodDoctor AI Chat</h1>
        <a href="/" class="back-btn">← Back</a>
    </div>
    <div class="chat-container">
        <div class="messages" id="messages">
            <div class="message assistant">
                <div class="message-bubble">
                    Hello! I'm MoodDoctor AI. You can type messages, upload images of your face, or record your voice. How are you feeling today?
                </div>
            </div>
        </div>
        <div class="input-area">
            <div class="file-controls">
                <label class="file-btn">
                    📷 Upload Image
                    <input type="file" id="imageInput" accept="image/*">
                </label>
                <button class="file-btn" id="voiceBtn">
                    🎤 Speak
                </button>
            </div>
            <div id="filePreview"></div>
            <div class="input-group">
                <input type="text" id="messageInput" placeholder="Type your message..." onkeypress="if(event.key==='Enter') sendMessage()">
                <button id="sendButton" onclick="sendMessage()">Send</button>
            </div>
        </div>
    </div>
    
    <script>
        let conversationId = 'chat_' + Date.now();
        let selectedImage = null;
        let audioChunks = [];
        let mediaRecorder = null;
        let isRecording = false;
        
        // Image upload handler
        document.getElementById('imageInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                selectedImage = file;
                const reader = new FileReader();
                reader.onload = function(e) {
                    showFilePreview(file.name, e.target.result, 'image');
                };
                reader.readAsDataURL(file);
            }
        });
        
        // Voice recording handler
        document.getElementById('voiceBtn').addEventListener('click', async function() {
            if (!isRecording) {
                try {
                    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                    mediaRecorder = new MediaRecorder(stream);
                    audioChunks = [];
                    
                    mediaRecorder.ondataavailable = function(event) {
                        audioChunks.push(event.data);
                    };
                    
                    mediaRecorder.onstop = function() {
                        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                        selectedAudio = audioBlob;
                        showFilePreview('Recording.webm', URL.createObjectURL(audioBlob), 'audio');
                        stream.getTracks().forEach(track => track.stop());
                    };
                    
                    mediaRecorder.start();
                    isRecording = true;
                    this.textContent = '⏹️ Stop';
                    this.classList.add('recording');
                } catch (error) {
                    alert('Microphone access denied. Please allow microphone access.');
                }
            } else {
                mediaRecorder.stop();
                isRecording = false;
                this.textContent = '🎤 Speak';
                this.classList.remove('recording');
            }
        });
        
        let selectedAudio = null;
        
        function showFilePreview(filename, preview, type) {
            const previewDiv = document.getElementById('filePreview');
            previewDiv.innerHTML = `
                <div class="file-preview">
                    ${type === 'image' ? `<img src="${preview}" alt="Preview">` : `<audio controls src="${preview}" style="max-width: 200px;"></audio>`}
                    <span>${filename}</span>
                    <button onclick="clearFiles()">×</button>
                </div>
            `;
        }
        
        function clearFiles() {
            selectedImage = null;
            selectedAudio = null;
            document.getElementById('imageInput').value = '';
            document.getElementById('filePreview').innerHTML = '';
            if (isRecording && mediaRecorder) {
                mediaRecorder.stop();
                isRecording = false;
                document.getElementById('voiceBtn').textContent = '🎤 Speak';
                document.getElementById('voiceBtn').classList.remove('recording');
            }
        }
        
        async function sendMessage() {
            const input = document.getElementById('messageInput');
            const sendButton = document.getElementById('sendButton');
            const message = input.value.trim();
            
            if (!message && !selectedImage && !selectedAudio) return;
            
            // Disable input
            input.disabled = true;
            sendButton.disabled = true;
            
            // Add user message
            if (message) {
                addMessage('user', message);
            }
            if (selectedImage) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    addImageMessage('user', e.target.result);
                };
                reader.readAsDataURL(selectedImage);
            }
            if (selectedAudio) {
                addMessage('user', '🎤 Voice message sent');
            }
            
            input.value = '';
            
            // Show loading
            const loadingId = addMessage('assistant', 'Thinking...');
            
            try {
                let response;
                
                if (selectedImage || selectedAudio) {
                    // Use multimodal endpoint
                    const formData = new FormData();
                    if (message) formData.append('text', message);
                    if (selectedImage) formData.append('face_image', selectedImage);
                    if (selectedAudio) formData.append('voice_audio', selectedAudio);
                    formData.append('conversation_id', conversationId);
                    
                    response = await fetch('/api/v1/mood/multimodal', {
                        method: 'POST',
                        body: formData
                    });
                } else {
                    // Use text-only endpoint
                    response = await fetch('/api/v1/mood/text', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            text: message || 'User shared nonverbal signals',
                            conversation_id: conversationId
                        })
                    });
                }
                
                const data = await response.json();
                
                // Remove loading
                removeMessage(loadingId);
                
                // Add assistant response
                addMessage('assistant', data.response_text || 'I understand.');
                
                // Clear files
                clearFiles();
                
            } catch (error) {
                removeMessage(loadingId);
                addMessage('assistant', 'Sorry, an error occurred. Please try again.');
                console.error('Error:', error);
            } finally {
                input.disabled = false;
                sendButton.disabled = false;
                input.focus();
            }
        }
        
        function addMessage(role, content) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            messageDiv.id = 'msg_' + Date.now();
            
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            bubble.textContent = content;
            
            messageDiv.appendChild(bubble);
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            
            return messageDiv.id;
        }
        
        function addImageMessage(role, imageSrc) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            const img = document.createElement('img');
            img.src = imageSrc;
            img.className = 'message-image';
            bubble.appendChild(img);
            
            messageDiv.appendChild(bubble);
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function removeMessage(messageId) {
            const msg = document.getElementById(messageId);
            if (msg) msg.remove();
        }
    </script>
</body>
</html>
        """)

    # Admin training UI - password protected, then same chat UI
    @app.get("/train", response_class=HTMLResponse)
    async def train_page():
        """Admin chat page - password prompt first, then same chat UI as /chat."""
        return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MoodDoctor AI - Admin Chat</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: white;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: white;
            border-bottom: 1px solid #ddd;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 24px;
            font-weight: 600;
            color: #333;
        }
        .back-btn {
            padding: 8px 16px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
            cursor: pointer;
        }
        #passwordPrompt {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .password-container {
            max-width: 400px;
            width: 100%;
            padding: 40px;
        }
        .password-container h2 {
            font-size: 20px;
            margin-bottom: 20px;
            color: #333;
        }
        .password-container input {
            width: 100%;
            padding: 12px 18px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            margin-bottom: 15px;
            outline: none;
        }
        .password-container input:focus {
            border-color: #999;
        }
        .password-container button {
            width: 100%;
            padding: 12px 24px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-weight: 600;
            cursor: pointer;
        }
        .password-container button:hover {
            border-color: #999;
        }
        .error {
            color: #d32f2f;
            font-size: 13px;
            margin-top: 10px;
        }
        #chatUI {
            display: none;
            flex: 1;
            flex-direction: column;
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            overflow: hidden;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: white;
        }
        .message {
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
        }
        .message.user {
            align-items: flex-end;
        }
        .message.assistant {
            align-items: flex-start;
        }
        .message-bubble {
            max-width: 70%;
            padding: 12px 18px;
            border-radius: 5px;
            word-wrap: break-word;
            border: 1px solid #e0e0e0;
        }
        .message.user .message-bubble {
            background: #f5f5f5;
            color: #333;
        }
        .message.assistant .message-bubble {
            background: #f5f5f5;
            color: #333;
        }
        .message-image {
            max-width: 200px;
            border-radius: 5px;
            margin-top: 5px;
        }
        .input-area {
            padding: 20px;
            background: white;
            border-top: 1px solid #ddd;
        }
        .file-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }
        .file-btn {
            padding: 10px 16px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .file-btn:hover {
            border-color: #999;
        }
        .file-btn input[type="file"] {
            display: none;
        }
        .file-preview {
            margin-bottom: 10px;
            padding: 8px;
            background: #f5f5f5;
            border-radius: 5px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .file-preview img {
            max-width: 50px;
            max-height: 50px;
            border-radius: 5px;
        }
        .file-preview button {
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 18px;
        }
        .input-group {
            display: flex;
            gap: 10px;
        }
        #messageInput {
            flex: 1;
            padding: 12px 18px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            outline: none;
        }
        #messageInput:focus {
            border-color: #999;
        }
        #sendButton {
            padding: 12px 24px;
            background: white;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-weight: 600;
            cursor: pointer;
        }
        #sendButton:hover {
            border-color: #999;
        }
        #sendButton:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .recording {
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛠️ Admin Chat</h1>
        <a href="/" class="back-btn">← Back</a>
    </div>
    
    <!-- Password Prompt -->
    <div id="passwordPrompt">
        <div class="password-container">
            <h2>Admin Access Required</h2>
            <input type="password" id="adminPasswordInput" placeholder="Enter ADMIN_PASSWORD from .env" onkeypress="if(event.key==='Enter') authenticate()">
            <button onclick="authenticate()">Authenticate</button>
            <div id="passwordError" class="error"></div>
        </div>
    </div>
    
    <!-- Chat UI (shown after authentication) -->
    <div id="chatUI" class="chat-container">
        <div class="messages" id="messages">
            <div class="message assistant">
                <div class="message-bubble">
                    Hello! I'm MoodDoctor AI in Admin Mode. Your conversations will be saved as training examples. How can I help you today?
                </div>
            </div>
        </div>
        <div class="input-area">
            <div class="file-controls">
                <label class="file-btn">
                    📷 Upload Image
                    <input type="file" id="imageInput" accept="image/*">
                </label>
                <button class="file-btn" id="voiceBtn">
                    🎤 Speak
                </button>
            </div>
            <div id="filePreview"></div>
            <div class="input-group">
                <input type="text" id="messageInput" placeholder="Type your message..." onkeypress="if(event.key==='Enter') sendMessage()">
                <button id="sendButton" onclick="sendMessage()">Send</button>
            </div>
        </div>
    </div>
    
    <script>
        let adminPassword = '';
        let conversationId = 'admin_' + Date.now();
        let selectedImage = null;
        let audioChunks = [];
        let mediaRecorder = null;
        let isRecording = false;
        let selectedAudio = null;
        
        // Check if already authenticated
        window.addEventListener('DOMContentLoaded', function() {
            const saved = localStorage.getItem('admin_authenticated');
            const savedPassword = localStorage.getItem('admin_password');
            if (saved === 'true' && savedPassword) {
                adminPassword = savedPassword;
                showChatUI();
            }
        });
        
        async function authenticate() {
            const passwordInput = document.getElementById('adminPasswordInput');
            const password = passwordInput.value.trim();
            const errorDiv = document.getElementById('passwordError');
            
            if (!password) {
                errorDiv.textContent = 'Please enter a password.';
                return;
            }
            
            // Verify password by trying to access a protected endpoint
            try {
                const res = await fetch('/api/v1/train/examples?admin_password=' + encodeURIComponent(password));
                if (res.ok || res.status === 200) {
                    adminPassword = password;
                    localStorage.setItem('admin_authenticated', 'true');
                    localStorage.setItem('admin_password', password);
                    showChatUI();
                } else {
                    errorDiv.textContent = 'Invalid password. Please try again.';
                }
            } catch (e) {
                // If endpoint doesn't exist or error, still allow (for dev)
                adminPassword = password;
                localStorage.setItem('admin_authenticated', 'true');
                localStorage.setItem('admin_password', password);
                showChatUI();
            }
        }
        
        function showChatUI() {
            document.getElementById('passwordPrompt').style.display = 'none';
            document.getElementById('chatUI').style.display = 'flex';
            initChatHandlers();
        }
        
        function initChatHandlers() {
            // Image upload handler
            document.getElementById('imageInput').addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file) {
                    selectedImage = file;
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        showFilePreview(file.name, e.target.result, 'image');
                    };
                    reader.readAsDataURL(file);
                }
            });
            
            // Voice recording handler
            document.getElementById('voiceBtn').addEventListener('click', async function() {
                if (!isRecording) {
                    try {
                        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                        mediaRecorder = new MediaRecorder(stream);
                        audioChunks = [];
                        
                        mediaRecorder.ondataavailable = function(event) {
                            audioChunks.push(event.data);
                        };
                        
                        mediaRecorder.onstop = function() {
                            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                            selectedAudio = audioBlob;
                            showFilePreview('Recording.webm', URL.createObjectURL(audioBlob), 'audio');
                            stream.getTracks().forEach(track => track.stop());
                        };
                        
                        mediaRecorder.start();
                        isRecording = true;
                        this.textContent = '⏹️ Stop';
                        this.classList.add('recording');
                    } catch (error) {
                        alert('Microphone access denied. Please allow microphone access.');
                    }
                } else {
                    mediaRecorder.stop();
                    isRecording = false;
                    this.textContent = '🎤 Speak';
                    this.classList.remove('recording');
                }
            });
        }
        
        function showFilePreview(filename, preview, type) {
            const previewDiv = document.getElementById('filePreview');
            previewDiv.innerHTML = `
                <div class="file-preview">
                    ${type === 'image' ? `<img src="${preview}" alt="Preview">` : `<audio controls src="${preview}" style="max-width: 200px;"></audio>`}
                    <span>${filename}</span>
                    <button onclick="clearFiles()">×</button>
                </div>
            `;
        }
        
        function clearFiles() {
            selectedImage = null;
            selectedAudio = null;
            document.getElementById('imageInput').value = '';
            document.getElementById('filePreview').innerHTML = '';
            if (isRecording && mediaRecorder) {
                mediaRecorder.stop();
                isRecording = false;
                document.getElementById('voiceBtn').textContent = '🎤 Speak';
                document.getElementById('voiceBtn').classList.remove('recording');
            }
        }
        
        async function sendMessage() {
            const input = document.getElementById('messageInput');
            const sendButton = document.getElementById('sendButton');
            const message = input.value.trim();
            
            if (!message && !selectedImage && !selectedAudio) return;
            
            // Disable input
            input.disabled = true;
            sendButton.disabled = true;
            
            // Add user message
            if (message) {
                addMessage('user', message);
            }
            if (selectedImage) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    addImageMessage('user', e.target.result);
                };
                reader.readAsDataURL(selectedImage);
            }
            if (selectedAudio) {
                addMessage('user', '🎤 Voice message sent');
            }
            
            input.value = '';
            
            // Show loading
            const loadingId = addMessage('assistant', 'Thinking...');
            
            try {
                let response;
                
                if (selectedImage || selectedAudio) {
                    // Use multimodal endpoint with admin_password
                    const formData = new FormData();
                    if (message) formData.append('text', message);
                    if (selectedImage) formData.append('face_image', selectedImage);
                    if (selectedAudio) formData.append('voice_audio', selectedAudio);
                    formData.append('conversation_id', conversationId);
                    formData.append('admin_password', adminPassword);
                    
                    response = await fetch('/api/v1/mood/multimodal', {
                        method: 'POST',
                        body: formData
                    });
                } else {
                    // Use text-only endpoint with admin_password
                    response = await fetch('/api/v1/mood/text', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            text: message || 'User shared nonverbal signals',
                            conversation_id: conversationId,
                            admin_password: adminPassword
                        })
                    });
                }
                
                const data = await response.json();
                
                // Remove loading
                removeMessage(loadingId);
                
                // Add assistant response
                addMessage('assistant', data.response_text || 'I understand.');
                
                // Clear files
                clearFiles();
                
            } catch (error) {
                removeMessage(loadingId);
                addMessage('assistant', 'Sorry, an error occurred. Please try again.');
                console.error('Error:', error);
            } finally {
                input.disabled = false;
                sendButton.disabled = false;
                input.focus();
            }
        }
        
        function addMessage(role, content) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            messageDiv.id = 'msg_' + Date.now();
            
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            bubble.textContent = content;
            
            messageDiv.appendChild(bubble);
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            
            return messageDiv.id;
        }
        
        function addImageMessage(role, imageSrc) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            const img = document.createElement('img');
            img.src = imageSrc;
            img.className = 'message-image';
            bubble.appendChild(img);
            
            messageDiv.appendChild(bubble);
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function removeMessage(messageId) {
            const msg = document.getElementById(messageId);
            if (msg) msg.remove();
        }
    </script>
</body>
</html>
        """)

    # Docs route (standard Swagger UI)
    @app.get("/docs", include_in_schema=False)
    async def docs():
        from fastapi.openapi.docs import get_swagger_ui_html
        return get_swagger_ui_html(openapi_url=app.openapi_url, title=app.title + " - Swagger UI")

    # API Routers
    app.include_router(mood.router, prefix="/api/v1/mood", tags=["mood"])
    app.include_router(stream.router, prefix="/api/v1/mood", tags=["stream"])
    app.include_router(train.router, prefix="/api/v1/train", tags=["train"])
    
    # Authentication Router
    from app.api.v1.endpoints import auth
    app.include_router(auth.router, prefix="/api/v1", tags=["authentication"])

    @app.on_event("startup")
    async def on_startup() -> None:  # pragma: no cover - simple side effect
        logger.info("MoodDoctor backend starting up")

    @app.on_event("shutdown")
    async def on_shutdown() -> None:  # pragma: no cover - simple side effect
        logger.info("MoodDoctor backend shutting down")

    return app


app = create_app()


