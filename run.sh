#!/bin/zsh
set -e
cd "$(dirname "$0")/backend"
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
