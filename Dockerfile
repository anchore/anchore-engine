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

RUN yum -y update && yum -y install epel-release && yum -y install git skopeo python34 python34-tools python34-devel python34-pip dpkg psmisc && yum clean all -y
RUN pip3 install --upgrade pip && pip3 install --upgrade setuptools wheel

RUN pip3 install -e git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli


COPY --from=wheelbuilder /wheels /wheels
COPY . /anchore-engine

WORKDIR /anchore-engine
RUN pip3 install --no-index --find-links=/wheels -r requirements.txt && pip3 install .

CMD /usr/bin/anchore-manager service start
