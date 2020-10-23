package main

import (
	"nextensio/controller/db"
	"nextensio/controller/router"
	"nextensio/controller/utils"
)

func initAll(readonly bool) {
	db.DBInit()
	router.RouterInit(readonly)
}

// The NXT Server runs in a read-write mode, where admins can configure / provision agents etc.
// The NXT Controller runs in a read-only mode where it can purely read off the database and handle
// sign on requests from agents etc. The code is the same, we just dont register the read-write http
// routes in the controller
func main() {
	readonly := utils.GetEnv("NXT_READONLY", "true")
	if readonly == "true" {
		initAll(true)
	} else {
		initAll(false)
	}
	// wait on REST calls for ever
	router.ServeRoutes()
}
