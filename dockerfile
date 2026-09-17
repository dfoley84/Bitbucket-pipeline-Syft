FROM python:3.14-slim
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
       jq \
       bash \
       ca-certificates \
       findutils \
    && rm -rf /var/lib/apt/lists/*

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Python pipe dependencies
RUN pip install --no-cache-dir bitbucket-pipes-toolkit==6.2.0

COPY pipe.py /pipe.py
COPY pipe.sh /pipe.sh
COPY pr_comment.py /pr_comment.py
RUN chmod +x /pipe.sh

WORKDIR /workspace

ENTRYPOINT ["python3", "/pipe.py"]
