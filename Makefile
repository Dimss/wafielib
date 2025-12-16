image:
	podman buildx build --build-arg ARCH=arm64 -t docker.io/wafieio/modsec --platform linux/arm64 .
	podman push docker.io/wafieio/modsec