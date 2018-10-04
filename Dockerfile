FROM centos:7

ENV LANG=en_US.UTF-8
EXPOSE 8228 8338 8087 8082

RUN yum -y update && yum -y install epel-release && yum -y install skopeo python-pip dpkg gcc python-devel openssl-devel psmisc && yum clean all -y && rm -rf /var/cache/yum

ENV TINI_VERSION=v0.18.0
RUN cd /tmp && \
  gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 && \
  gpg --fingerprint 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 | grep -q "Key fingerprint = 6380 DC42 8747 F6C3 93FE  ACA5 9A84 159D 7001 A4E5" && \
  curl -sSL https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini.asc -o tini.asc && \
  curl -sSL https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini -o /usr/local/bin/tini && \
  gpg --verify tini.asc /usr/local/bin/tini && \
  chmod +x /usr/local/bin/tini && \
  rm tini.asc

RUN pip install --upgrade pip && pip install --upgrade setuptools && pip install anchorecli

COPY . /root/anchore-engine
RUN cd /root/anchore-engine/ && pip install --upgrade .

ENTRYPOINT ["/usr/local/bin/tini", "--"]
CMD ["/usr/bin/anchore-engine"]
