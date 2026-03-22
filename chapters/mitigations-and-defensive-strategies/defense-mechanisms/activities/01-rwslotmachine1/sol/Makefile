IMAGE_NAME = ransomware1
CONTAINER_NAME = ransomware1_container
PORT = 31344

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME) .

# Run the Docker container
run:
	docker run -it --rm -p $(PORT):$(PORT) --name $(CONTAINER_NAME) $(IMAGE_NAME)

# Stop the Docker container
stop:
	docker stop $(CONTAINER_NAME)

# Clean up the Docker image
clean:
	docker rmi $(IMAGE_NAME)
