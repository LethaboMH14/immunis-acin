@echo off
echo Starting IMMUNIS ACIN...
echo.
pip install -r requirements.txt --quiet
echo.
echo Starting server on port 8000...
uvicorn backend.main:app --reload --port 8000 --host 0.0.0.0
