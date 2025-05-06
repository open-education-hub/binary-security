PORT ?= 31347
IMG_NAME ?= rwslotmachine4
CONT_NAME ?= $(IMG_NAME)-cnt

build:
	docker build -t $(IMG_NAME) -f Dockerfile .

run: build
	docker run -d --rm -p $(PORT):31337 --name $(CONT_NAME) -t $(IMG_NAME)

stop:
	-docker stop $(CONT_NAME)

clean: stop
	docker rm $(CONT_NAME)

.PHONY: build run stop clean
