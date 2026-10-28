FROM python@sha256:1acc95d63ef1c8cc902e9a10a8ae080e1377325771d2819beb48156e1b3b9673
RUN apk upgrade --no-cache && adduser -D -u 10001 probe
WORKDIR /probe
COPY tests/identitycontract/diagnostic_consumer.py tests/identitycontract/rehearsal.py tests/identitycontract/verifier.py ./
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8443
HEALTHCHECK NONE
ENTRYPOINT ["python", "-B", "/probe/diagnostic_consumer.py", "/run/f02/diagnostic.json"]
