FROM centos:latest

ENV LANG=en_US.UTF-8
EXPOSE 80

RUN yum -y update && yum -y install epel-release && yum -y install skopeo python-pip dpkg gcc python-devel openssl-devel && yum clean all -y
RUN pip install --upgrade pip && pip install --upgrade setuptools 

COPY ./anchore-engine /root/anchore-engine
COPY ./anchore-cli /root/anchore-cli
COPY ./anchore /root/anchore

RUN cd /root/anchore-engine/ && pip install --upgrade . && cd /root/anchore/ && pip install --upgrade . && cd /root/anchore-cli/ && pip install --upgrade .
# RUN pip uninstall -y enum34; pip uninstall -y enum; pip install enum==0.4.6

CMD /usr/bin/anchore-engine

#
# TO USE
#
# docker run --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres
# emacs -nw /root/anchore-engine-configfiles/config.yaml
# docker run -v /var/run/docker.sock:/var/run/docker.sock -v /root/anchore-engine-configfiles/:/config/ -p 8080:80 -d --name anchore-engine anchore-engine
#
# curl -XPOST -u admin:foobar http://localhost:8080/v1/images -d'{"tag":"alpine"}'
# curl -XPOST -u admin:foobar http://localhost:8080/v1/policies -d"@/root/somebundle.json"
# curl -u admin:foobar http://localhost:8080/v1/images
# curl -u admin:foobar http://localhost:8080/v1/images/<img_url_id>
# curl -u admin:foobar http://localhost:8080/v1/images/<img_url_id>/check
# ....
#
