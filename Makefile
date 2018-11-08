install:
	go build -o dist/mynetes main.go
	sudo mv dist/mynetes /usr/local/bin/