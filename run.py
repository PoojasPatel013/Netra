import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

from netra.main import app

if __name__ == "__main__":
    app()
