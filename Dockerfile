FROM golang:latest AS golang-builder

COPY . /tmp/build/.

# Avoid error where Go cannot determine current user:
ENV USER=root

# Build project:
RUN make --directory /tmp/build build

FROM        quay.io/prometheus/busybox:latest
LABEL       maintainer="Maxime Wojtczak <maxime.wojtczak@zenika.com>"

COPY --from=golang-builder /tmp/build/snmp_notifier /bin/snmp_notifier

EXPOSE      9464
ENTRYPOINT  [ "/bin/snmp_notifier" ]
