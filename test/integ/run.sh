#!/usr/bin/env bash

# Kill any previous incarnations of the controller and fake-oauth daemons
pkill -9 nxtsvr
pkill -9 oauth_fake

# Build the nxtsvr and oauth freshly, and launch them
cd nxtsvr
go build
NXT_READONLY=false ./nxtsvr>/dev/null 2>&1 &

cd ../test/oauth_fake
go build
./oauth_fake&

# Now build and run the integ tests
cd ../integ
go build; go test 
