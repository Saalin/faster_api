FROM python:3.12-alpine

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

CMD ["uvicorn", "--app-dir", "/app", "app.main:app", "--host", "0.0.0.0", "--port", "80"]