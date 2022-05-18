FROM python:3.10-alpine as builder
RUN apk update && apk add --update cargo gcc rust make musl-dev python3-dev libffi-dev openssl-dev

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY ./requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

FROM python:3.10-alpine
RUN apk add musl-dev
WORKDIR mhddos_proxy
COPY --from=builder	/opt/venv /opt/venv
COPY . .
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["python3", "./runner.py"]
