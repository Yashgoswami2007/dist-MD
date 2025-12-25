import sys
import os

# Add current directory to path (cwd is GIT_SRC)
sys.path.append(os.getcwd())

print(f"Testing import of app.main from {os.getcwd()}...")

try:
    import app.main
    print("✅ SUCCESS: app.main imported successfully.")
except ImportError as e:
    print(f"❌ IMPORT ERROR: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ OTHER ERROR: {e}")
    sys.exit(1)
