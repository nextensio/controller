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
go build; 

# The test cases cant run in parallel unfortunately because they all work with
# the same DB - we can partition the DB per test case etc. to make this faster,
# but thats not done today, a TODO for later, till then run in serial
for t in `cat ./test_cases.txt`;
do
  go test -run $t
done

