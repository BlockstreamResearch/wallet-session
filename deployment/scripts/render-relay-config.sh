#!/bin/sh
# Render the relay configuration from the deployment templates, then exec the
# relay. Runs as the container entrypoint.
set -eu

CONFIG_DIR="/app/configuration"
TEMPLATE_DIR="/deployment/configs/relay"

# Only these placeholders are substituted, so any other `$` in the templates
# (there is none today) or in the environment is left alone.
PLACEHOLDERS='${RELAY_PORT} ${HEALTH_PORT} ${APPLICATION_AUDIENCE} ${MAX_TOKEN_LIFETIME_SECONDS}'

: "${APPLICATION_AUDIENCE:?APPLICATION_AUDIENCE must be set (see deployment/configs/compose.env)}"
: "${RELAY_PORT:?RELAY_PORT must be set (see deployment/configs/compose.env)}"
: "${HEALTH_PORT:?HEALTH_PORT must be set (see deployment/configs/compose.env)}"
: "${MAX_TOKEN_LIFETIME_SECONDS:?MAX_TOKEN_LIFETIME_SECONDS must be set (see deployment/configs/compose.env)}"

mkdir -p "$CONFIG_DIR"

for name in base production; do
  envsubst "$PLACEHOLDERS" <"$TEMPLATE_DIR/$name.yaml.template" >"$CONFIG_DIR/$name.yaml"
done

exec "$@"
