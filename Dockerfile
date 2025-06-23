FROM python:3.12

COPY ./src /app

COPY ./requirements.txt /requirements.txt

COPY ./external_packages /external_packages

RUN pip install -r /requirements.txt --no-cache-dir
RUN pip install /external_packages/dpss-0.0.0-py3-none-any.whl

EXPOSE 5000

ENTRYPOINT ["python", "/app/main.py"]
