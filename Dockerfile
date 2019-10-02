FROM python:3.7-slim-stretch

# Many of these dependencies are required to build the app's dependencies, so staging these out doesn't help much
RUN mkdir -p /app
RUN apt-get update && apt-get install -y git gcc clang cmake pkg-config libdbus-1-dev libglib2.0-dev libcairo2-dev python3-dev libgirepository1.0-dev wget

WORKDIR /app
RUN wget https://gitlab.matrix.org/matrix-org/olm/-/archive/master/olm-master.tar.bz2 \
    && tar -xvf olm-master.tar.bz2 \
    && cd olm-master && make && make PREFIX="/usr" install && cd ../ \
    && rm -r olm-master

COPY . /app
RUN pip install . gobject PyGObject "matrix-nio@git+https://github.com/poljar/matrix-nio.git@dev#egg=matrix-nio-0" && python setup.py install

VOLUME /data
ENTRYPOINT ["pantalaimon"]
CMD ["-c", "/data/pantalaimon.conf"]
