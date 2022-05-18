FROM --platform=$BUILDPLATFORM python:3.10-alpine as builder
RUN apk update && apk add --update cargo gcc rust make musl-dev python3-dev libffi-dev openssl-dev

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY ./requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

FROM --platform=$BUILDPLATFORM python:3.10-alpine
COPY --from=builder	/opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR mhddos_proxy
COPY . .
ENTRYPOINT ["python3", "./runner.py"]
