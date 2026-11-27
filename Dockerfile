FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y ophcrack-cli unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tables
COPY tables_xp_free_fast.zip /tmp/table.zip
RUN unzip -q /tmp/table.zip -d /tables && rm /tmp/table.zip

COPY pwdump.txt /root/pwdump.txt
WORKDIR /root
CMD ["/bin/bash"]
