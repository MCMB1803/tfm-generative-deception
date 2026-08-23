# Control arm: a genuine, unmodified Debian host with a real OpenSSH server.
#
# This is the baseline the decoy is measured against. It is deliberately NOT
# dressed up -- no planted history, no synthetic business files, no honeytokens.
# Everything the attacker sees here is produced by the real coreutils, the real
# /proc, the real sshd. A fresh install with no lived-in history is a perfectly
# ordinary real host, and using a vanilla one keeps the comparison honest: if
# the judge can separate the arms, it is separating "generated" from "real",
# not "elaborately decorated" from "bare".
#
# Reachable only on loopback via the compose port mapping, and only under the
# `eval` profile, so it never runs as part of the normal stack.
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server procps iproute2 net-tools coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Password login as root, so the same attacker/harness credentials reach both
# arms unchanged. Acceptable only because this host is loopback-only and lives
# in an isolated evaluation profile; it is not a production configuration.
ARG ROOT_PASSWORD=honeypot
RUN echo "root:${ROOT_PASSWORD}" | chpasswd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
