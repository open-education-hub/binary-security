PORT ?= 31348
IMG_NAME ?= rwslotmachine5
CONT_NAME ?= $(IMG_NAME)-cnt

build:
	docker build -t $(IMG_NAME) -f Dockerfile .

run: build
	docker run -d -p $(PORT):31348 --name $(CONT_NAME) -t $(IMG_NAME)

stop:
	-docker stop $(CONT_NAME)

clean: stop
	docker rm $(CONT_NAME)

.PHONY: build run stop clean
