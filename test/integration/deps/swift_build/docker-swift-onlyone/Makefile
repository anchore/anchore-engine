
SWIFT_USER_PASSWORD=testing
CNTR=onlyone
CNTR_IMAGE=swift-onlyone
DATA_CNTR=SWIFT_DATA
DATA_CNTR_IMAGE=busybox
LOCAL_PORT=12345
DOCKER_PORT=8080

all: build delete run_swift_data run_swift

redeploy: delete build run_swift

run_swift_data:
	-docker run \
  	-v /srv \
	--name $(DATA_CNTR) \
    $(DATA_CNTR_IMAGE)	

run_swift:
	docker run \
	--name $(CNTR) \
	--hostname $(CNTR) \
	-e "SWIFT_USER_PASSWORD=$(SWIFT_USER_PASSWORD)" \
	-d \
	-p $(LOCAL_PORT):$(DOCKER_PORT) \
	--volumes-from $(DATA_CNTR) \
	-t $(CNTR_IMAGE) 

delete:
	-docker rm -f $(CNTR) 

bash:
	docker exec -i -t $(CNTR) /bin/bash

build:
	docker build -t $(CNTR_IMAGE) .

logs:
	docker logs $(CNTR) 
