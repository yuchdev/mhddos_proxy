FROM --platform=$BUILDPLATFORM python:3.10-buster as builder
WORKDIR mhddos_proxy
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "./runner.py"]
