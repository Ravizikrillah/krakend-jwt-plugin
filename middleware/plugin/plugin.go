package main

import (
	"context"
	"errors"
	"fmt"
	"krakend-plugin/middleware/gateway"
	"net/http"
	"time"
)

func init() {
	fmt.Println("middleware plugin loaded!!!")
}

var ClientRegisterer = registerer("middleware")

type registerer string

func (r registerer) RegisterClients(f func(
	name string,
	handler func(context.Context, map[string]interface{}) (http.Handler, error),
)) {
	f(string(r), func(ctx context.Context, extra map[string]interface{}) (http.Handler, error) {
		cfg := parse(extra)
		if cfg == nil {
			return nil, errors.New("wrong config")
		}
		if cfg.name != string(r) {
			return nil, fmt.Errorf("unknown register %s", cfg.name)
		}
		return gateway.New(ctx, cfg.name, cfg.roles, gateway.Config{
			JwtSecretKey:  "your-jwt-secret",
			ClientTimeout: time.Second * 10,
		})
	})
}

func parse(extra map[string]interface{}) *opts {
	name, ok := extra["name"].(string)
	if !ok {
		return nil
	}
	roles := make([]float64, 10)
	roleClaims, ok := extra["roles"].([]interface{})
	if !ok {
		roles[0] = 0
	} else {
		for i, v := range roleClaims {
			roles[i] = v.(float64)
		}
	}

	return &opts{
		name:  name,
		roles: roles,
	}
}

type opts struct {
	name  string
	roles []float64
}

func main() {}
