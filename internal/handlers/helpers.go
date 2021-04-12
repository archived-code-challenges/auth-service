package handlers

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func getQueryList(r *http.Request, queryString string, outType interface{}) (interface{}, error) {
	urlKeys := strings.Split(r.URL.Query().Get(queryString), ",")

	switch reflect.ValueOf(outType).Interface().(type) {
	case []int64:
		newSlice := make([]int64, 0, len(urlKeys))
		for _, item := range urlKeys {
			if item != "" {
				n, err := strconv.ParseInt(item, 10, 64)
				if err != nil {
					return nil, errors.New("wrong format for number")
				}
				newSlice = append(newSlice, n)
			}
		}
		return newSlice, nil

	case []string:
		newSlice := make([]string, 0, len(urlKeys))
		for _, item := range urlKeys {
			if item != "" {
				newSlice = append(newSlice, item)
			}
		}
		return newSlice, nil

	default:
		return nil, errors.New("outType not supported")
	}
}
