# Nextensio Server/Controller

Nextensio Server and Controller shares the exact same code base, the only difference
is that the server is a read-write entity whereas controllers operate in a read-only
mode. Servers are what allows admins to configure nextensio tenants/agents etc. and 
controllers allow agents to use configured data and sign on etc.

The source code is organized as individual small packages which are combined together
to form the server/controller. This package demarcation is intentional to try and 
ensure/enforce modularity while designing/coding. The directory layout is as follows

# Code Organization:

## nxtsvr:
this code generates the binary for the next server/controller

## utils:
miscellaneous utilities used by all packages

## db:
the database code, currently mongodb, but having it seperated out into a package
of its own should one day allow us to swap it out with some other database if needed

## test/integ:
Integration test cases which assume the nxt server is running and then makes API calls
to configure various stuff and reads and ensures the configurations are as expected etc.

## test/oauth_fake:
For the integration tests to run, we dont want to rely on an external oauth entity, so
we just fake whatever oauth stuff we need using a fake oauth server

# Integration Testing:

From the root of the controller/ workspace, run test/integ/run.sh. If all the tests pass,
you should see lines like below. 

PASS
ok  	nextensio/controller/test/integ	0.093s

If there is error, it will say FAIL and also details of the test/line number that failed.
Also after the test is complete, the controller and fake oauth keeps running in case someone
wants to debug something with a gdb etc. Running the test (run.sh) again will restart the 
processes

