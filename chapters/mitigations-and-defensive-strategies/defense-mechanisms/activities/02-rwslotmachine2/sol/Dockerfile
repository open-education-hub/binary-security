# Build Stage
FROM gcc:latest AS build

# Set working directory
WORKDIR /app

# Copy the source code into the container
COPY rwslotmachine2.c .

# Compile the source code into an executable
RUN gcc rwslotmachine2.c -o rwslotmachine2 -Wall -Wextra

# Runtime Stage
# FROM debian:bullseye-slim
FROM ubuntu:latest

# Install necessary runtime libraries
RUN apt-get update && apt-get install -y \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the compiled executable from the builder stage
# COPY --from=build /app/rwslotmachine2 .
COPY --from=build /app/rwslotmachine2 /app/rwslotmachine2

# Expose the port where the program will operate
EXPOSE 31345

# Run the program
CMD ["./rwslotmachine2"]
