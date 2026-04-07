FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV OPENAI_API_KEY=""
ENV HF_TOKEN=""
ENV MODEL_NAME="gpt-4"
ENV API_BASE_URL="https://api.openai.com/v1"
ENV USE_MOCK="false"
ENV PORT="7860"

CMD ["python", "server/app.py"]
