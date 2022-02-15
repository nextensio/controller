VERSION=latest
NAME=controller
USER=registry.gitlab.com/nextensio/controller
image=$(shell docker images $(USER)/$(NAME):$(VERSION) -q)

.PHONY: all
all: build

.PHONY: build
build:
	rm -r -f files/version
	echo $(VERSION) > files/version
	docker build -f Dockerfile.build -t $(USER)/$(NAME):$(VERSION) .
	docker create $(USER)/$(NAME):$(VERSION)

.PHONY: clean
clean:
	-rm -r -f files/version
