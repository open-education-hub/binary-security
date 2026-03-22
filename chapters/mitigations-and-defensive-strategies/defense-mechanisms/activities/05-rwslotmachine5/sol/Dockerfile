# --- Build ---
FROM gcc:latest AS builder

WORKDIR /app

COPY ./rwslotmachine5.c .

RUN gcc -o rwslotmachine5 rwslotmachine5.c

# --- Runtime ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libstdc++6 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/rwslotmachine5 .

EXPOSE 31348

CMD ["/app/rwslotmachine5"]
