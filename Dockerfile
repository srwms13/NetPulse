FROM python:3.10-slim

WORKDIR /app

# Install nmap
RUN apt-get update && apt-get install -y nmap

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
