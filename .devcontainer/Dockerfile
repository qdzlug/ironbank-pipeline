FROM registry1.dso.mil/ironbank-apps/ironbank-pipelines/pipeline-runner:0.11.0

USER 0

RUN dnf install -y sudo; \
  groupmod -g 1000 python; \
  usermod -s /bin/bash -u 1000 -aG wheel python; \
  echo '%wheel ALL=(ALL) NOPASSWD: ALL' | tee -a /etc/sudoers

ENV PYTHONPATH=/home/python/ironbank-modules/ironbank \
  VIRTUAL_ENV_DISABLE_PROMPT=1

ENTRYPOINT [ "/bin/bash" ]