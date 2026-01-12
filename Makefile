image:
	podman manifest rm libmodsec --ignore
	podman build \
      --manifest libmodsec \
      --platform linux/arm64,linux/amd64 .
	podman manifest push libmodsec docker.io/wafieio/modsec