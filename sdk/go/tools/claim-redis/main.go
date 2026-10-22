// Test-only cross-SDK probe. Use only an explicitly owned disposable Redis.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	appguard "github.com/bonjin-app/appguard/sdk/go"
	"github.com/redis/go-redis/v9"
)

func run(args []string) error {
	if len(args) != 6 {
		return fmt.Errorf("invalid probe input")
	}
	options, err := redis.ParseURL(args[0])
	if err != nil {
		return fmt.Errorf("invalid probe input")
	}
	host, _, err := net.SplitHostPort(options.Addr)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return fmt.Errorf("probe requires owned disposable loopback Redis")
	}
	now, err := strconv.ParseInt(args[4], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid probe input")
	}
	expires, err := strconv.ParseInt(args[5], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid probe input")
	}
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.PoolTimeout = time.Second
	client := redis.NewClient(options)
	defer client.Close()
	store, err := appguard.NewRedisReplayStore(client)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted, err := store.Claim(ctx, appguard.ReplayScope{AppID: args[1], KeyID: args[2], Nonce: args[3]}, expires, now)
	if err != nil {
		return fmt.Errorf("REPLAY_STORE_UNAVAILABLE")
	}
	if accepted {
		fmt.Println("CLAIMED")
	} else {
		fmt.Println("REPLAY")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "REDIS_PROBE_FAILED")
		os.Exit(1)
	}
}
