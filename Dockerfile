FROM python:3.8-slim-buster AS builder

# Many of these dependencies are required to build the app's dependencies, so staging these out doesn't help much
RUN mkdir -p /app
RUN apt-get update && apt-get install -y git gcc clang cmake pkg-config libdbus-1-dev libglib2.0-dev libcairo2-dev python3-dev libgirepository1.0-dev wget

WORKDIR /app
RUN wget https://gitlab.matrix.org/matrix-org/olm/-/archive/master/olm-master.tar.bz2 \
    && tar -xvf olm-master.tar.bz2 \
    && cd olm-master && make && make PREFIX="/usr" install

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
