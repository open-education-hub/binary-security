PORT_BUILD ?= 32000
PORT_RUNTIME ?= 32001
IMG_BUILD ?= rwslotmachine3_build
IMG_RUNTIME ?= rwslotmachine3_runtime
CONT_BUILD ?= $(IMG_BUILD)-cnt
CONT_RUNTIME ?= $(IMG_RUNTIME)-cnt

create_build:
	docker build -t $(IMG_BUILD) --target=build -f Dockerfile ..

create_runtime:
	docker build -t $(IMG_RUNTIME) --target=runtime -f Dockerfile ..

run_build:
	docker run -d --rm -p $(PORT_BUILD):31346 --name $(CONT_BUILD) -t $(IMG_BUILD)

run_runtime:
	docker run -d --rm -p $(PORT_RUNTIME):31346 --name $(CONT_RUNTIME) -t $(IMG_RUNTIME)

stop_build:
	-docker stop $(CONT_BUILD)

stop_runtime:
	-docker stop $(CONT_RUNTIME)

stop_all: stop_build stop_runtime

clean_build: stop_build
	docker rm $(CONT_BUILD)

clean_runtime: stop_runtime
	docker rm $(CONT_RUNTIME)

clean_all: clean_build clean_runtime

.PHONY: create_build create_runtime run_build run_runtime \
        stop_all stop_build stop_runtime clean clean_build clean_runtime
