# Build pip wheels for all dependencies
FROM centos:7 as wheelbuilder

ARG CLI_COMMIT=master

LABEL anchore_cli_commit=$ANCHORE_COMMIT

ENV LANG=en_US.UTF-8
EXPOSE 8228 8338 8087 8082

RUN yum -y update && yum -y install epel-release && yum -y install python34 python34-devel git skopeo python34-pip dpkg psmisc gcc && yum clean all -y
RUN pip3 install --upgrade pip && pip3 install --upgrade setuptools wheel

RUN pip3 install -e git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli

COPY . /anchore-engine
WORKDIR /anchore-engine
RUN pip3 wheel --wheel-dir=/wheels -r requirements.txt

# Do the final build
FROM centos:7

ARG CLI_COMMIT=master

LABEL anchore_cli_commit=$ANCHORE_COMMIT

ENV LANG=en_US.UTF-8
EXPOSE 8228 8338 8087 8082

RUN yum -y update && yum -y install epel-release && yum -y install git skopeo python34 python34-tools python34-devel python34-pip dpkg psmisc && yum clean all -y && rm -rf /var/cache/yum

ENV TINI_VERSION=v0.18.0
RUN cd /tmp && \
  gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 && \
  gpg --fingerprint 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 | grep -q "Key fingerprint = 6380 DC42 8747 F6C3 93FE  ACA5 9A84 159D 7001 A4E5" && \
  curl -sSL https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini.asc -o tini.asc && \
  curl -sSL https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini -o /usr/local/bin/tini && \
  gpg --verify tini.asc /usr/local/bin/tini && \
  chmod +x /usr/local/bin/tini && \
  rm tini.asc

RUN pip3 install --upgrade pip && pip3 install --upgrade setuptools wheel
RUN pip3 install -e git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli

COPY --from=wheelbuilder /wheels /wheels
COPY . /anchore-engine

WORKDIR /anchore-engine
RUN pip3 install --no-index --find-links=/wheels -r requirements.txt && pip3 install .

ENTRYPOINT ["/usr/local/bin/tini", "--"]
CMD ["/usr/bin/anchore-manager", "service", "start"]
