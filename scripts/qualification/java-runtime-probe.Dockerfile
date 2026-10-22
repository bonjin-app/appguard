# Diagnostic comparison only. This image is not the production backend.
# Keep the entire vendor JRE, including legal, release, security and native files.
FROM eclipse-temurin:17-jre-noble@sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd AS vendor_jre
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
COPY --from=vendor_jre /opt/java/openjdk/ /opt/java/openjdk/
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=/opt/java/openjdk/bin:$PATH
ENV JAVA_VERSION=jdk-17.0.20.1+1
ENV LANG=C.UTF-8
# Rebuild the final OS loader cache; do not copy Noble system libraries/cache.
RUN set -eu; \
    find "$JAVA_HOME/lib" -name '*.so' -exec dirname '{}' ';' | sort -u > /etc/ld.so.conf.d/docker-openjdk.conf; \
    ldconfig
USER 10001:10001
ENTRYPOINT ["/opt/java/openjdk/bin/java"]
