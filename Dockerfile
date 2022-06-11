FROM --platform=$TARGETPLATFORM python:3.10-slim

RUN apt-get update && apt-get -y install git
RUN python3 -m venv /opt/venv
ENV IS_DOCKER=1 PATH="/opt/venv/bin:$PATH"

COPY ./requirements.txt .
RUN pip install --no-cache-dir -U pip wheel && pip install --no-cache-dir --only-binary=:all: -r requirements.txt

RUN git clone https://github.com/porthole-ascend-cinnamon/mhddos_proxy.git
WORKDIR mhddos_proxy

ENTRYPOINT ["./runner.sh", "python3"]
