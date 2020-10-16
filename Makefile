VERSION=0.1
NAME=controller
USER=registry.gitlab.com/nextensio/controller
image=$(shell docker images $(USER)/$(NAME):$(VERSION) -q)
bimage=$(shell docker images $(USER)/$(NAME)-build:$(VERSION) -q)
dimage=$(shell docker images $(USER)/$(NAME)-debug:$(VERSION) -q)
acontid=$(shell docker ps -a --filter ancestor=$(USER)/$(NAME):$(VERSION) -q)
abcontid=$(shell docker ps -a --filter ancestor=$(USER)/$(NAME)-build:$(VERSION) -q)
adcontid=$(shell docker ps -a --filter ancestor=$(USER)/$(NAME)-debug:$(VERSION) -q)
bcontid=$(shell docker ps -a --filter ancestor=$(USER)/$(NAME)-build:$(VERSION) -q | head -n 1)

.PHONY: all
all: test

.PHONY: test
test:
	rm -r -f files/version
	echo $(VERSION) > files/version
	docker build -f Dockerfile.test -t $(USER)/$(NAME)-test:$(VERSION) .
	docker create $(USER)/$(NAME)-test:$(VERSION)

.PHONY: clean
clean:
	-docker rm $(acontid)
	-docker rm $(abcontid)
	-docker rm $(adcontid)
	-docker rmi $(image)
	-docker rmi $(bimage)
	-docker rmi $(dimage)
	-rm -r -f files/version
