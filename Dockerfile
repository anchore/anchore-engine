FROM centos:latest

ENV LANG=en_US.UTF-8
EXPOSE 8228 8338

RUN yum -y update && yum -y install epel-release && yum -y install skopeo python-pip dpkg gcc python-devel openssl-devel && yum clean all -y
RUN pip install --upgrade pip && pip install --upgrade setuptools 

COPY ./anchore-engine /root/anchore-engine
COPY ./anchore-cli /root/anchore-cli
COPY ./anchore /root/anchore

RUN cd /root/anchore-engine/ && pip install --upgrade . && cd /root/anchore/ && pip install --upgrade . && cd /root/anchore-cli/ && pip install --upgrade .

CMD /usr/bin/anchore-engine
