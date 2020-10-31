FROM registry:2.7.0
MAINTAINER Samuel Dacanay <sam@anchore.com>

# Note: I originally tried loading these into the container at runtime, but circle CI did not play nice with volumes
# This does make the image more ephemeral which is nice, but it will get re-built each execution
COPY ./auth /auth
COPY ./certs /certs