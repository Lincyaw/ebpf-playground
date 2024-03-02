

generate:
	go generate ./...

clean:
	find . \( -name "*eb.go" -o -name "*el.go" -o -name "*eb.o" -o -name "*el.o" \) -exec rm {} +
