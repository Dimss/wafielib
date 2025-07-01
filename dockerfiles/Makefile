build: copy
	docker buildx build --push -t dimssss/wafie-agent:latest -f Dockerfile_go .
copy:
	cp ../cmake-build-debug/libwafie.so ./
	cp ../include/wafielib.h ./include/wafie/
	cp ../cmake-build-debug/libwafie.so /Users/dkartsev/.go/src/github.com/Dimss/wafie/cmd/modsecfilter
	cp ../include/wafielib.h /Users/dkartsev/.go/src/github.com/Dimss/wafie/cmd/modsecfilter/include/wafie
build-modsec-runtime:
	docker buildx build --load -t modsec .
