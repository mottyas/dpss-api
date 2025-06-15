FROM python:3.12

COPY . /app

COPY ./requirements.txt /requirements.txt

RUN pip install -r /requirements.txt --no-cache-dir

EXPOSE 8000

ENTRYPOINT ["python", "/app/main.py"]
