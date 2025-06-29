build: copy
	docker buildx build --push -t dimssss/kubeguard-agent:latest -f Dockerfile_go .
copy:
	cp ../cmake-build-debug/libkubeguard.so ./
	cp ../include/kubeguardlib.h ./include/kubeguard/
	cp ../cmake-build-debug/libkubeguard.so /Users/dkartsev/.go/src/github.com/Dimss/cwaf/cmd/modsecfilter
	cp ../include/kubeguardlib.h /Users/dkartsev/.go/src/github.com/Dimss/cwaf/cmd/modsecfilter/include/kubeguard
build-modsec-runtime:
	docker buildx build --load -t modsec .
