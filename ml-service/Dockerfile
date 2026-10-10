FROM python:3.13-slim
WORKDIR /service
COPY ml-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ml-service ./
EXPOSE 8000
CMD ["python", "run.py"]
