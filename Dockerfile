FROM ubuntu:26.10

RUN apt update
RUN apt install -y opam libexpat1-dev libgtk2.0-dev pkg-config python3 graphviz python3-venv
RUN opam init --disable-sandboxing
RUN opam install -y proverif
ENV PATH="$PATH:/root/.opam/default/bin"
RUN apt install -y pip

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv ${VIRTUAL_ENV}

WORKDIR /compareverif
COPY . .
RUN /opt/venv/bin/pip install -r Requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT []