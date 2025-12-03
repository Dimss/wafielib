image:
	podman buildx build --build-arg ARCH=arm64 -t docker.io/dimssss/modsec --platform linux/arm64 .
	podman push docker.io/dimssss/modsec