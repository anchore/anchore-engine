# hadolint ignore=DL3006
FROM alpine

# installs ruby, then bundler via gem
# next, it install Python3, and uses pip to install pytest
# finally it removes the cache - all in one go to prevent another layer which we don't need
RUN set -ex && \
# install ruby, and then bundler \
    apk --no-cache add ruby=2.7.1-r3 ruby-dev=2.7.1-r3 && \
    gem install bundler:2.1.4 && \
# install python, pip,  and pytest \
    apk add --no-cache python3=3.8.5-r0 && \
    python3 -m ensurepip && \
    pip3 install pytest==6.1.1 && \
    rm -rf /var/cache/apk/* && \
# remove languages and their dependencies \
    apk --no-cache del gmp ncurses-terminfo-base ncurses-libs readline yaml libgcc libstdc++ libgmpxx pkgconf gmp-dev && \
    apk --no-cache del python3 ca-certificates libbz2 expat libffi gdbm xz-libs sqlite-libs

# create WORKDIR
ENV WORKDIR /srv/current
RUN mkdir $WORKDIR
WORKDIR $WORKDIR
