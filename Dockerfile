FROM zlim/bcc
ENV GOPATH=/home/user/go
WORKDIR /home/user
RUN mkdir -p /home/user/go/src/github.com/alban/golang-ebpf/
RUN apt-get update -y && apt-get install -y bash runit conntrack iproute2 util-linux curl python bcc-tools python-bcc libbcc vim strace gdb golang

