# Stage 1: Build
FROM ubuntu:22.04 AS builder

WORKDIR /app

RUN set -xe; \
    apt-get -yqq update; \
    apt-get -yqq install build-essential \
    ;

COPY ./rwslotmachine4.c .
COPY ./Makefile.sol ./Makefile

RUN make

# Stage 2: Runtime
FROM ubuntu:22.04

RUN set -xe; \
     apt-get -yqq update;\
     apt-get -yqq install libstdc++6; \
     rm -rf /var/lib/apt/lists/* \
;

WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /app/rwslotmachine4 .

# Expose port
EXPOSE 31347

# Run the executable
CMD ["/app/rwslotmachine4"]
