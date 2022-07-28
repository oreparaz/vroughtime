FROM gcr.io/oss-fuzz-base/base-builder
# RUN apt-get update
COPY . $SRC/vroughtime
WORKDIR $SRC/vroughtime
COPY .clusterfuzzlite/build.sh $SRC/build.sh