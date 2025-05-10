FROM debian:11 AS build

ARG CHALLENGE_NAME="03-rwslotmachine"
ARG USER_NAME="rwslotmachine3"

RUN useradd -m -d /home/${USER_NAME} -s /bin/bash ${USER_NAME}
RUN mkdir /home/${USER_NAME}/${CHALLENGE_NAME}

COPY sol/rwslotmachine3.c /home/${USER_NAME}/${CHALLENGE_NAME}/
COPY sol/Makefile /home/${USER_NAME}/${CHALLENGE_NAME}/

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc-multilib make libc6-dev:i386

WORKDIR /home/${USER_NAME}/${CHALLENGE_NAME}
RUN make build

RUN chown -R root:rwslotmachine3 /home/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}/Makefile

FROM debian:11 AS runtime

ARG CHALLENGE_NAME="03-rwslotmachine"
ARG USER_NAME="rwslotmachine3"

RUN useradd -m -d /home/${USER_NAME} -s /bin/bash ${USER_NAME}
RUN mkdir /home/${USER_NAME}/${CHALLENGE_NAME}

RUN apt-get update && \
    apt-get install -y make && \
    apt-get install -y procps && rm -rf /var/lib/apt/lists/* && \
    apt-get update && apt-get install -y iproute2

COPY --from=build /home/rwslotmachine3/03-rwslotmachine/rwslotmachine3 \
     /home/rwslotmachine3/03-rwslotmachine/
COPY --from=build /home/rwslotmachine3/03-rwslotmachine/Makefile \
     /home/rwslotmachine3/03-rwslotmachine/

COPY src/ld-linux.so.2 /home/${USER_NAME}/${CHALLENGE_NAME}/ld-linux.so.2
COPY src/libc.so.6 /home/${USER_NAME}/${CHALLENGE_NAME}/libc.so.6

WORKDIR /home/${USER_NAME}/${CHALLENGE_NAME}
RUN make check_binary

RUN chown -R root:rwslotmachine3 /home/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}/rwslotmachine3
RUN chmod 750 /home/rwslotmachine3/${CHALLENGE_NAME}/Makefile

CMD ["./ld-linux.so.2", "--library-path", ".", "./rwslotmachine3", "31346"]
