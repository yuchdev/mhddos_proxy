FROM --platform=$BUILDPLATFORM python:3.10-alpine as builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY ./requirements.txt .
RUN pip3 install --no-cache-dir --extra-index-url https://alpine-wheels.github.io/index -r requirements.txt

FROM --platform=$BUILDPLATFORM python:3.10-alpine
WORKDIR mhddos_proxy
COPY --from=builder	/opt/venv /opt/venv
COPY . .
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["python3", "./runner.py"]
