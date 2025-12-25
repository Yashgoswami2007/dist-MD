# MoodDoctor Backend (Production Ready)

This folder contains the clean, essential backend code for MoodDoctor.

## Deployment to Render

1.  **Repo**: Create a new GitHub repository and push the contents of this `GIT_SRC` folder (as the root).
2.  **Render Settings**:
    *   **Build Command**: `pip install -r requirements.txt`
    *   **Start Command**: `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`
3.  **Environment Variables**:
    *   Copy values from your `production_config.txt` (or `.env`).
    *   Ensure `MONGODB_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GEMINI_API_KEY`, etc. are set.

## Local Development

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```
