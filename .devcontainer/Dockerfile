FROM registry1.dso.mil/ironbank/ironbank-pipelines/pipeline-runner-dev:v0.0.5

ENV GECKO_VERSION="0.33.0" \
    VENV=/home/python/.work \
    VIRTUAL_ENV_DISABLE_PROMPT=1

# gecko
RUN if [ "$(uname -i)" = "x86_64" ]; then GECKO_ARCH="linux64"; else GECKO_ARCH="linux-aarch64"; fi && \
    curl -fLs -o - "https://github.com/mozilla/geckodriver/releases/download/v${GECKO_VERSION}/geckodriver-v${GECKO_VERSION}-$GECKO_ARCH.tar.gz" | tar -xz -C /home/python/.local/bin/ -f -

# poetry
RUN pip install --user poetry && \
    install -d -m 0750 -o python ${VENV}
COPY pyproject.toml ./
COPY stages ./
RUN python -m venv $VENV && \
    PATH=$VENV/bin:$PATH VIRTUAL_ENV=$VENV poetry install --no-root --no-directory --compile