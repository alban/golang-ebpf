#!/bin/bash
sudo docker run --rm -it \
	--privileged --net=host --pid=host \
	-v $PWD:/home/user/go/src/github.com/alban/golang-ebpf \
	-v /lib/modules:/lib/modules \
	-v /usr/src:/usr/src \
	albanc/toolbox-bcc:latest

