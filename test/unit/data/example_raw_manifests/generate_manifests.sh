#!/bin/bash

REPOLIST="aerospike alpine arangodb backdrop bonita buildpack-deps busybox cassandra celery centos chronograf cirros clojure consul couchbase couchdb crate crux debian django docker drupal elixir erlang fedora gazebo gcc ghost glassfish golang haproxy haskell hello-seattle hello-world hipache hola-mundo httpd hylang influxdb iojs irssi java jenkins jetty joomla jruby julia kaazing-gateway kapacitor lightstreamer mageia mariadb maven memcached mongo mongo-express mono mysql nats neo4j neurodebian nginx node nuxeo odoo opensuse oraclelinux orientdb owncloud percona perl photon php php-zendserver piwik postgres pypy python rabbitmq rails rakudo-star r-base redis redmine registry rethinkdb rocket.chat ros ruby sentry solr sonarqube sourcemage swarm telegraf thrift tomcat tomee traefik ubuntu websphere-liberty wordpress dnurmi/testrepo cloudfleet/nginx"

for i in ${REPOLIST}
do 
    echo Fetching top level manifest for docker.io/${i}:latest
    NAME=`echo ${i} | sed "s/\//_/g"`    
    skopeo inspect --raw docker://docker.io/${i}:latest > ${NAME}.json
    skopeo manifest-digest ${NAME}.json > ${NAME}.json.digest
done

for i in ${REPOLIST}
do 
    NAME=`echo ${i} | sed "s/\//_/g"`
    D=`cat ${NAME}.json |grep amd64 -B2 | grep digest | awk -F'"' '{print $4}' | head -n 1`
    if [ ! -z ${D} ]; then
	echo Fetching arch amd64 level manifest for docker.io/${i}@${D}
	skopeo inspect --raw docker://docker.io/${i}@${D} > ${NAME}-arch.json
	skopeo manifest-digest ${NAME}-arch.json > ${NAME}-arch.json.digest
    fi
done
