
all: clean proxy server client
proxy: 
	go build cmd/proxy/main.go

server: 
	go build cmd/server/main.go

client: 
	go build cmd/client/main.go

clean: clean-server clean-proxy clean-client

run-proxy: clean-proxy
	go run cmd/proxy/main.go

run-server: clean-server
	go run cmd/server/main.go	

run-client: clean-client
	go run cmd/client/main.go	

clean-proxy:
	rm -rf proxy

clean-server:
	rm -rf server

clean-client:
	rm -rf client
