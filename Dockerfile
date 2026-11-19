FROM python:3.12-slim
WORKDIR /app
ENV CARNETSATS_VPUB=""
ENV GROQ_API_KEY=""
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pytest test_carnetsats.py
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
