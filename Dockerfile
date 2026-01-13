# syntax=docker/dockerfile:1.4

# Sentinel MQTT Gateway Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-mqtt-agent /sentinel-mqtt-agent

LABEL org.opencontainers.image.title="Sentinel MQTT Gateway Agent" \
      org.opencontainers.image.description="Sentinel MQTT Gateway Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-mqtt-gateway"

ENV RUST_LOG=info,sentinel_mqtt_agent=debug \
    SOCKET_PATH=/var/run/sentinel/mqtt.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-mqtt-agent"]
