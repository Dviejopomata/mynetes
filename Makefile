install:
	go build -o dist/na-cli main.go
	sudo mv dist/na-cli /usr/local/bin/