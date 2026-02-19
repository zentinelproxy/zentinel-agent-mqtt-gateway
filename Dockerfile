# syntax=docker/dockerfile:1.4

# Zentinel MQTT Gateway Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-mqtt-gateway-agent /zentinel-mqtt-gateway-agent

LABEL org.opencontainers.image.title="Zentinel MQTT Gateway Agent" \
      org.opencontainers.image.description="Zentinel MQTT Gateway Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway"

ENV RUST_LOG=info,zentinel_mqtt_agent=debug \
    SOCKET_PATH=/var/run/zentinel/mqtt.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-mqtt-gateway-agent"]
