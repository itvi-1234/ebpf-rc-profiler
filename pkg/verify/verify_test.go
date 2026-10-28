package verify

import (
	"os"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// behaviors builds a service map for source "shop" from short descriptions.
func shopMap(behaviors ...string) []byte {
	return []byte("spec:\n  behaviors:\n" + strings.Join(behaviors, ""))
}

const (
	pgBehavior = `    - id: pg
      sourceRef: workload:container/shop
      destination: {workloadRef: workload:container/shop-db}
      facets:
        protocol: {name: postgres, category: database}
        network: {port: 5432, envNames: [DB_HOST, DB_PORT]}
`
	redisBehavior = `    - id: redis
      sourceRef: workload:container/shop
      destination: {workloadRef: workload:container/shop-cache}
      facets:
        protocol: {name: redis, category: cache}
        network: {port: 6379, envNames: [REDIS_URL]}
`
	apiBehavior = `    - id: api
      sourceRef: workload:container/shop
      destination: {workloadRef: workload:container/api.frankfurter.dev}
      facets:
        protocol: {name: tls}
        network: {port: 443, tls: true, serverName: api.frankfurter.dev, envNames: [EXCHANGE_API_URL]}
`
)

func run(t *testing.T, mapYAML []byte, service string) Report {
	t.Helper()
	profile, observed, err := Load(readFile(t, "testdata/shop.profile.yaml"), mapYAML)
	if err != nil {
		t.Fatal(err)
	}
	return Verify(profile, observed, service)
}

func levels(r Report) map[Level]int {
	counts := map[Level]int{}
	for _, f := range r.Findings {
		counts[f.Level]++
	}
	return counts
}

func TestFullyDeclaredShopPasses(t *testing.T) {
	r := run(t, shopMap(pgBehavior, redisBehavior, apiBehavior), "shop")
	if c := levels(r); c[OK] != 3 || len(r.Findings) != 3 || r.Failed() {
		t.Fatalf("unexpected report:\n%s", r)
	}
}

func TestUndeclaredDependencyFails(t *testing.T) {
	profile, observed, err := Load([]byte(`
conditions:
  - kind: datastore
    interface: {type: relational, engine: postgres}
    configuration: {env: [{name: DB_HOST, property: hostname}]}
`), shopMap(pgBehavior, redisBehavior))
	if err != nil {
		t.Fatal(err)
	}
	r := Verify(profile, observed, "shop")
	if !r.Failed() || !strings.Contains(r.String(), "cache/redis shop-cache:6379 was observed but no condition") {
		t.Fatalf("redis should be reported as undeclared:\n%s", r)
	}
}

func TestDeclaredButNotObservedIsOnlyInfo(t *testing.T) {
	r := run(t, shopMap(pgBehavior), "shop")
	c := levels(r)
	if r.Failed() || c[OK] != 1 || c[Info] != 2 {
		t.Fatalf("unexpected report:\n%s", r)
	}
}

func TestEnvMismatchWarns(t *testing.T) {
	wrongEnv := strings.Replace(pgBehavior, "[DB_HOST, DB_PORT]", "[PG_HOST]", 1)
	r := run(t, shopMap(wrongEnv, redisBehavior, apiBehavior), "shop")
	if r.Failed() || levels(r)[Warn] != 1 || !r.HasWarnings() {
		t.Fatalf("expected one env warning:\n%s", r)
	}
	if !strings.Contains(r.String(), "PG_HOST") {
		t.Fatalf("warning should name the env the process used:\n%s", r)
	}
}

func TestMessageBusWithoutExtensionIsReported(t *testing.T) {
	nats := `    - id: nats
      sourceRef: workload:container/shop
      destination: {workloadRef: workload:container/nats-server}
      facets:
        protocol: {name: nats, category: message_bus}
        network: {port: 4222}
`
	r := run(t, shopMap(pgBehavior, redisBehavior, apiBehavior, nats), "shop")
	if !r.Failed() || !strings.Contains(r.String(), "message buses need an extension") {
		t.Fatalf("unexpected report:\n%s", r)
	}
}

func TestServiceFilterIgnoresOtherWorkloads(t *testing.T) {
	r := run(t, shopMap(pgBehavior), "someone-else")
	if levels(r)[OK] != 0 || r.Failed() {
		t.Fatalf("nothing should match another service:\n%s", r)
	}
}

// The real output of the TLS test run: curl calling api.frankfurter.dev.
func TestRealTLSRunMatchesDeclaredAPI(t *testing.T) {
	r := run(t, readFile(t, "testdata/tls_run.map.yaml"), "tlstest")
	if r.Failed() {
		t.Fatalf("the HTTPS call is declared as an api condition:\n%s", r)
	}
	if !strings.Contains(r.String(), "api/http api.frankfurter.dev:443 is declared as api/http") {
		t.Fatalf("api should be matched:\n%s", r)
	}
	if c := levels(r); c[Info] != 2 {
		t.Fatalf("postgres and redis were not exercised by curl:\n%s", r)
	}
}
