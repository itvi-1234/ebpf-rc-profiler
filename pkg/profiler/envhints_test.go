//go:build linux

package profiler

import (
	"reflect"
	"testing"
)

func TestEnvNameHintsFindsHostAndPortVariables(t *testing.T) {
	env := map[string]string{
		"DB_HOST":     "shop-shop-db-postgresql.default.svc.cluster.local",
		"DB_PORT":     "5432",
		"DB_USER":     "postgres",
		"REDIS_URL":   "redis://shop-cache-master:6379",
		"UNRELATED":   "8080",
		"PATH":        "/usr/bin",
		"DB_PASSWORD": "hunter2",
	}
	got := envNameHints(env, []string{"shop-shop-db-postgresql.default.svc.cluster.local"}, 5432)
	want := []string{"DB_HOST", "DB_PORT"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("postgres: got %v, want %v", got, want)
	}

	got = envNameHints(env, []string{"shop-cache-master"}, 6379)
	if !reflect.DeepEqual(got, []string{"REDIS_URL"}) {
		t.Fatalf("redis: got %v", got)
	}
}

func TestEnvNameHintsMatchesWholeTokensOnly(t *testing.T) {
	env := map[string]string{"A": "notpostgres-1", "B": "postgres"}
	got := envNameHints(env, []string{"postgres"}, 5432)
	if !reflect.DeepEqual(got, []string{"B"}) {
		t.Fatalf("got %v", got)
	}
}

func TestEnvNameHintsPortAloneIsNotEnough(t *testing.T) {
	env := map[string]string{"SOME_PORT": "5432"}
	if got := envNameHints(env, []string{"db.internal"}, 5432); got != nil {
		t.Fatalf("got %v, want none", got)
	}
}

func TestEnvNameHintsHTTPSBaseURL(t *testing.T) {
	env := map[string]string{"EXCHANGE_API_URL": "https://api.frankfurter.dev/v1"}
	got := envNameHints(env, []string{"api.frankfurter.dev"}, 443)
	if !reflect.DeepEqual(got, []string{"EXCHANGE_API_URL"}) {
		t.Fatalf("got %v", got)
	}
}

func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("A=1\x00B=x=y\x00\x00=bad\x00C="))
	if env["A"] != "1" || env["B"] != "x=y" || env["C"] != "" || len(env) != 3 {
		t.Fatalf("got %v", env)
	}
}
