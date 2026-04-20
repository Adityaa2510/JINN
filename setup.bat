@echo off
echo ============================
echo  JINN Setup Script
echo ============================

echo Installing Python dependencies...
pip install -r requirements.txt

echo Starting Ollama...
start ollama serve

echo Pulling AI model...
ollama pull dolphin-llama3:8b

echo Starting DVWA (Docker required)...
docker run -d -p 80:80 vulnerables/web-dvwa

echo Starting Flask app...
python app.py

pause