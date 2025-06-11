build: copy
	docker buildx build --push -t dimssss/kubeguard-agent:latest -f Dockerfile_go .
copy:
	cp ../cmake-build-debug/libkubeguard.so ./
	cp ../include/kubeguardlib.h ./include/kubeguard/

build-modsec-runtime:
	docker buildx build --load -t modsec .
