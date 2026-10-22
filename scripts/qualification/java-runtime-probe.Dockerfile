# Diagnostic comparison only. No production backend is changed.
# The same dependency-free Java17 classes are compiled for both runtime targets.
FROM maven:3.9.16-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 AS probe_build
WORKDIR /probe
COPY scripts/qualification/java/AppGuardRuntimeProbe.java /probe/AppGuardRuntimeProbe.java
COPY LICENSE /probe/LICENSE
RUN javac --release 17 -encoding UTF-8 -d /probe/classes /probe/AppGuardRuntimeProbe.java

FROM eclipse-temurin:17-jre-noble@sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd AS vendor_jre
FROM vendor_jre AS baseline
COPY --from=probe_build /probe/classes/ /opt/appguard/java-runtime-probe/
COPY --from=probe_build /probe/LICENSE /usr/share/licenses/appguard/LICENSE
USER 10001:10001
ENTRYPOINT ["/opt/java/openjdk/bin/java"]

# Keep all vendor JRE bytes, including legal, release, security and native files.
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS debian-probe
COPY --from=vendor_jre /opt/java/openjdk/ /opt/java/openjdk/
COPY --from=probe_build /probe/classes/ /opt/appguard/java-runtime-probe/
COPY --from=probe_build /probe/LICENSE /usr/share/licenses/appguard/LICENSE
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
