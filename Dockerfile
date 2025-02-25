# Build arguments
ARG SOURCE_REGISTRY

# Dockerfile for building the VCS-scanner using a localy build version of the backend
FROM ${SOURCE_REGISTRY}python:3.12-alpine3.20

ARG NAME="resc-vcs-scanner"
ARG DESCRIPTION="RESC Version Control System Scanner"
ARG VERSION=${VERSION}
ARG RUN_AS_USER="apiuser"
ARG RUN_AS_GROUP="apiuser"
ARG UID=10001
ARG GID=10002
ARG GITLEAKS_VERSION="8.24.0"
ARG GITLEAKS_HASH="cb49b7de5ee986510fe8666ca0273a6cc15eb82571f2f14832c9e8920751f3a4" 

# Initialize Corporate configurations
# TODO add any files under rootfs that are needed for proxy settings
COPY rootfs/ /

RUN if [ -e init.sh ] ; then chmod +x /init.sh ; sh /init.sh; fi

# hadolint ignore=DL3018, ignore=DL3017, ignore=DL3018
RUN apk -U upgrade \
&& apk add --no-cache git \
&& apk add --no-cache --virtual .build-deps gcc g++ pcre-dev musl-dev python3-dev libffi-dev openssl-dev \
&& mkdir /vcs_scanner

COPY ./ /vcs_scanner

RUN addgroup -g $GID $RUN_AS_GROUP \
   && adduser -D -u $UID -G $RUN_AS_GROUP $RUN_AS_USER \
   && chown -R $RUN_AS_USER:$RUN_AS_GROUP /vcs_scanner \
   && wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
   && tar -zxvf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -C /vcs_scanner/gitleaks_config/ \
   && echo "$GITLEAKS_HASH  /vcs_scanner/gitleaks_config/gitleaks" > /tmp/gitleaks.sha256 \
   && sha256sum -c /tmp/gitleaks.sha256 \
   && if [ $? -eq 1 ]; then echo "Hash validation failed."; exit 1; fi \
   && mv /vcs_scanner/gitleaks_config/gitleaks /vcs_scanner/gitleaks_config/seco-gitleaks-linux-amd64 \
   && chmod +x /vcs_scanner/gitleaks_config/seco-gitleaks-linux-amd64

USER $RUN_AS_USER

ENV PATH=$PATH:/home/apiuser/.local/bin

# hadolint ignore=DL3013, ignore=DL3013
RUN pip install -U pip\
&& pip install -e /vcs_scanner

# Remove build dependencies, needs root
USER root
# hadolint ignore=DL3018
RUN apk --purge del .build-deps

USER $RUN_AS_USER

WORKDIR /vcs_scanner