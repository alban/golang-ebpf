#!/bin/bash
sudo docker run --rm -it \
	--privileged --net=host --pid=host \
	-v $PWD:/home/user/go/src/github.com/alban/golang-ebpf \
	albanc/toolbox-bcc:latest

