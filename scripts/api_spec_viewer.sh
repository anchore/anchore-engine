#!/usr/bin/env bash

usage=">api_spec_viewer.sh <service name> <port, default=8080>"

service_name=$1
port=$2

if [ -z "${port}" ]
then 
	port=8080
fi

connexion run --port ${port} anchore_engine/services/${service_name}/swagger/swagger.yaml --mock all
