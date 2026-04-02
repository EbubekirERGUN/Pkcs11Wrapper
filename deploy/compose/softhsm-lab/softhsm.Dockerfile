# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble
ARG APP_UID=64198
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bash ca-certificates opensc softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/opt/pkcs11/softhsm/softhsm2.conf \
    SOFTHSM_TOKEN_DIR=/opt/pkcs11/softhsm/tokens \
    PKCS11_MODULE_PATH=/opt/pkcs11/lib/libsofthsm2.so
COPY deploy/compose/softhsm-lab/scripts/ /opt/pkcs11-lab/scripts/
RUN chmod +x /opt/pkcs11-lab/scripts/*.sh \
    && mkdir -p /opt/pkcs11/lib /opt/pkcs11/softhsm/tokens \
    && ln -sf /usr/lib/softhsm/libsofthsm2.so /opt/pkcs11/lib/libsofthsm2.so \
    && ln -sf /opt/pkcs11-lab/scripts/seed-token.sh /usr/local/bin/seed-token \
    && ln -sf /opt/pkcs11-lab/scripts/show-objects.sh /usr/local/bin/show-objects \
    && chown -R ${APP_UID}:0 /opt/pkcs11 /opt/pkcs11-lab \
    && chmod -R g=u /opt/pkcs11 /opt/pkcs11-lab
VOLUME ["/opt/pkcs11/softhsm"]
USER ${APP_UID}
ENTRYPOINT ["/opt/pkcs11-lab/scripts/softhsm-entrypoint.sh"]
CMD ["serve"]
