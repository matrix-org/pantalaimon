FROM python:3.8-slim-buster AS builder

RUN mkdir -p /app
RUN apt-get update && apt-get install -y git gcc clang cmake g++ pkg-config python3-dev wget

WORKDIR /app

RUN wget https://gitlab.matrix.org/matrix-org/olm/-/archive/3.2.5/olm-3.2.5.tar.bz2 \
    && tar -xvf olm-3.2.5.tar.bz2 \
    && cd olm-3.2.5 && make && make PREFIX="/usr" install

RUN pip --no-cache-dir install --upgrade pip setuptools wheel

COPY . /app

RUN pip wheel . --wheel-dir /wheels --find-links /wheels

FROM python:3.8-slim-buster AS run

COPY --from=builder /usr/lib/libolm* /usr/lib/
COPY --from=builder /wheels /wheels
WORKDIR /app

RUN pip --no-cache-dir install --find-links /wheels --no-index pantalaimon

VOLUME /data
ENTRYPOINT ["pantalaimon"]
CMD ["-c", "/data/pantalaimon.conf", "--data-path", "/data"]
