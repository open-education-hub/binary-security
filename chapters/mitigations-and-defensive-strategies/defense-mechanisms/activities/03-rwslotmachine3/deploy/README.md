#Build, Run and Stop the container

- Build docker images for build and runtime stages:

	```bash
	make create_build
	make create_runtime
	```

- Run the containers:

	```bash
	make run_build
	make run_runtime
	```

- Stop the containers:

	```bash
	make stop_build
	make stop_runtime
	```

- Clean

	```bash
	make clean_all
	```

#Use the container and the executable

Build and run the runtime container and from host run:

	```bash
	nc 127.0.0.1 32001
	```
