FROM centos:7

ENV LANG=en_US.UTF-8
EXPOSE 8228 8338 8087 8082

RUN yum -y update && yum -y install epel-release && yum -y install skopeo-0.1.26-2.dev.git2e8377a.el7 python-pip dpkg gcc python-devel openssl-devel psmisc && yum clean all -y
RUN pip install --upgrade pip && pip install --upgrade setuptools && pip install anchorecli

COPY . /root/anchore-engine
RUN cd /root/anchore-engine/ && pip install --upgrade .

CMD /usr/bin/anchore-engine
