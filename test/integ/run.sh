#!/usr/bin/env bash

pkill -9 nxtsvr

cd nxtsvr
go build -tags unittest
NXT_READONLY=false ./nxtsvr>/dev/null 2>&1 &

cd ../test/integ
# The test cases cant run in parallel unfortunately because they all work with
# the same DB - we can partition the DB per test case etc. to make this faster,
# but thats not done today, a TODO for later, till then run in serial
for t in `cat ./test_cases.txt`;
do
  go test -run $t
done

