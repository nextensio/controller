package utils

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
)

func GetEnv(key string, defaultValue string) string {
	v := os.Getenv(key)
	if v == "" {
		v = defaultValue
	}
	return v
}

func GetEnvInt(key string, defaultValue int) int {
	v := os.Getenv(key)
	if v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			return val
		}
	}
	return defaultValue
}

func WriteResult(w http.ResponseWriter, result interface{}) {
	js, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.Write(js)
}
