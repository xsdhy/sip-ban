.PHONY: build clean run test daemon-start daemon-stop daemon-status daemon-restart

build:
	go build -o bin/sip-ban ./cmd/sip-ban

clean:
	rm -rf bin/

run: build
	sudo ./bin/sip-ban

test:
	go test ./...

install: build
	sudo cp bin/sip-ban /usr/local/bin/

# 以下 daemon-* 目标仅在 Linux 上有效，依赖 PID 文件 /var/run/sip-ban.pid 或自定义 PID。
# 可通过 `make daemon-start IFACE=eth0` 覆盖网卡名。
IFACE ?=

daemon-start: build
	sudo ./bin/sip-ban start -d $(if $(IFACE),-i $(IFACE),)

daemon-stop:
	sudo ./bin/sip-ban stop

daemon-status:
	./bin/sip-ban status

daemon-restart: build
	sudo ./bin/sip-ban restart $(if $(IFACE),-i $(IFACE),)

.DEFAULT_GOAL := build
