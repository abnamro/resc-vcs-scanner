FROM python:3.12-alpine3.20

ARG NAME="resc-vcs-scanner"
ARG DESCRIPTION="RESC Version Control System Scanner"
ARG VERSION=${VERSION}
ARG RUN_AS_USER="apiuser"
ARG RUN_AS_GROUP="apiuser"
ARG UID=10001
ARG GID=10002
ARG GITLEAKS_VERSION="8.18.4"
ARG GITLEAKS_HASH="46a05260e7cce527f132cb618de59d22262b8b5eb47f66c288447b95c7a98b7e"

RUN apk -U upgrade \
&& apk add --no-cache git \
&& apk add --no-cache --virtual .build-deps gcc g++ pcre-dev musl-dev python3-dev libffi-dev openssl-dev

RUN  mkdir /vcs_scanner

COPY ./ /vcs_scanner

RUN addgroup -g $GID $RUN_AS_GROUP \
   && adduser -D -u $UID -G $RUN_AS_GROUP $RUN_AS_USER \
   && chown -R $RUN_AS_USER:$RUN_AS_GROUP /vcs_scanner

RUN wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
   && tar -zxvf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -C /vcs_scanner/gitleaks_config/ \
   && echo "$GITLEAKS_HASH  /vcs_scanner/gitleaks_config/gitleaks" > /tmp/gitleaks.sha256 \
   && sha256sum -c /tmp/gitleaks.sha256 \
   && if [ $? -eq 1 ]; then echo "Hash validation failed."; exit 1; fi \
   && mv /vcs_scanner/gitleaks_config/gitleaks /vcs_scanner/gitleaks_config/seco-gitleaks-linux-amd64 \
   && chmod +x /vcs_scanner/gitleaks_config/seco-gitleaks-linux-amd64

USER $RUN_AS_USER

ENV PATH=$PATH:/home/apiuser/.local/bin

RUN pip install --no-cache-dir --upgrade -e /vcs_scanner

USER root

RUN apk --purge del .build-deps

USER $RUN_AS_USER

WORKDIR /vcs_scanner