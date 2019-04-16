#!/bin/bash

#
# Make the rings if they don't exist already
#

# These can be set with docker run -e VARIABLE=X at runtime
SWIFT_PART_POWER=${SWIFT_PART_POWER:-7}
SWIFT_PART_HOURS=${SWIFT_PART_HOURS:-1}
SWIFT_REPLICAS=${SWIFT_REPLICAS:-1}

if [ -e /srv/account.builder ]; then
	echo "Ring files already exist in /srv, copying them to /etc/swift..."
	cp /srv/*.builder /etc/swift/
	cp /srv/*.gz /etc/swift/
fi

# This comes from a volume, so need to chown it here, not sure of a better way
# to get it owned by Swift.
if [ ! -e /srv/node ]; then
  mkdir /srv/node
fi
chown -R swift:swift /srv

if [ ! -e /etc/swift/account.builder ]; then

	cd /etc/swift

	# 2^& = 128 we are assuming just one drive
	# 1 replica only

	echo "No existing ring files, creating them..."

	swift-ring-builder object.builder create ${SWIFT_PART_POWER} ${SWIFT_REPLICAS} ${SWIFT_PART_HOURS}
	swift-ring-builder object.builder add r1z1-127.0.0.1:6010/sdb1 1
	swift-ring-builder object.builder rebalance
	swift-ring-builder container.builder create ${SWIFT_PART_POWER} ${SWIFT_REPLICAS} ${SWIFT_PART_HOURS}
	swift-ring-builder container.builder add r1z1-127.0.0.1:6011/sdb1 1
	swift-ring-builder container.builder rebalance
	swift-ring-builder account.builder create ${SWIFT_PART_POWER} ${SWIFT_REPLICAS} ${SWIFT_PART_HOURS}
	swift-ring-builder account.builder add r1z1-127.0.0.1:6012/sdb1 1
	swift-ring-builder account.builder rebalance

	# Back these up for later use
	echo "Copying ring files to /srv to save them if it's a docker volume..."
	cp *.gz /srv
	cp *.builder /srv

fi

# If you are going to put an ssl terminator in front of the proxy, then I believe
# the storage_url_scheme should be set to https. So if this var isn't empty, set
# the default storage url to https.
if [ ! -z "${SWIFT_STORAGE_URL_SCHEME}" ]; then
	echo "Setting default_storage_scheme to https in proxy-server.conf..."
	sed -i -e "s/storage_url_scheme = default/storage_url_scheme = https/g" /etc/swift/proxy-server.conf
	grep "storage_url_scheme" /etc/swift/proxy-server.conf
fi

if [ ! -z "${SWIFT_USER_PASSWORD}" ]; then
	echo "Setting passwords in /etc/swift/proxy-server.conf"
	PASS=`pwgen 12 1`
	sed -i -e "s/user_admin_admin = admin .admin .reseller_admin/user_admin_admin = ${SWIFT_USER_PASSWORD} .admin .reseller_admin/g" /etc/swift/proxy-server.conf
	sed -i -e "s/user_test_tester = testing .admin/user_test_tester = ${SWIFT_USER_PASSWORD} .admin/g" /etc/swift/proxy-server.conf
	sed -i -e "s/user_test2_tester2 = testing2 .admin/user_test2_tester2 = ${SWIFT_USER_PASSWORD} .admin/g" /etc/swift/proxy-server.conf
	sed -i -e "s/user_test_tester3 = testing3/user_test_tester3 = ${SWIFT_USER_PASSWORD}/g" /etc/swift/proxy-server.conf
	grep "user_test" /etc/swift/proxy-server.conf
fi

# Start supervisord
echo "Starting supervisord..."
/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf

#
# Tail the log file for "docker log $CONTAINER_ID"
#

# sleep waiting for rsyslog to come up under supervisord
sleep 3

echo "Starting to tail /var/log/syslog...(hit ctrl-c if you are starting the container in a bash shell)"

tail -n 0 -f /var/log/syslog
