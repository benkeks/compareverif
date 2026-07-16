FROM ubuntu:26.10

RUN apt update
RUN apt install -y opam libexpat1-dev libgtk2.0-dev pkg-config python3
RUN opam init --disable-sandboxing
RUN opam install -y proverif
ENV PATH="$PATH:/root/.opam/default/bin"
RUN apt install -y pip

WORKDIR /compareverif
COPY . .
RUN pip3 install --break-system-packages -r Requirements.txt

ENTRYPOINT []