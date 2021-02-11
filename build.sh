#!/usr/bin/env zsh
go get -v all

GOOS=linux go build -o build/main cmd/main.go
zip -jrm build/main.zip build/main
