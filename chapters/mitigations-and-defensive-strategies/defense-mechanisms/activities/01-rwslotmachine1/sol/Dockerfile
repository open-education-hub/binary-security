# Stage 1: Build Stage
FROM gcc:latest AS build

WORKDIR /app

COPY rwslotmachine1.c .
COPY Makefile.sol Makefile

RUN make

# Stage 2: Runtime Stage
FROM ubuntu:latest

WORKDIR /app

COPY --from=build /app/rwslotmachine1 /app/rwslotmachine1

EXPOSE 31344

# Run the application
CMD ["./rwslotmachine1"]
