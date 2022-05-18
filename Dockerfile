FROM --platform=$BUILDPLATFORM python:3.10-buster as builder
WORKDIR mhddos_proxy
COPY ./requirements.txt .
RUN pip3 install --target=/mhddos_proxy/dependencies -r requirements.txt
COPY . .

FROM python:3.10-slim-buster
WORKDIR mhddos_proxy
COPY --from=builder	/mhddos_proxy .
ENV PYTHONPATH="${PYTHONPATH}:/mhddos_proxy/dependencies" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "./runner.py"]
