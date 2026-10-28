// rc-verify checks a declared Runtime Conditions profile against the behavior
// the eBPF profiler observed.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/runtimeconditions/ebpf-rc-profiler/pkg/verify"
)

func main() {
	profilePath := flag.String("profile", "", "declared Runtime Conditions profile (YAML)")
	mapPath := flag.String("map", "", "service map written by the profiler (SERVICE_MAP_PATH)")
	service := flag.String("service", "", "only check this service (the ADI_PROFILE_NAME of the process)")
	strict := flag.Bool("strict", false, "also fail on env wiring warnings")
	flag.Parse()

	if *profilePath == "" || *mapPath == "" {
		fmt.Fprintln(os.Stderr, "usage: rc-verify --profile profile.yaml --map service-map.yaml [--service name] [--strict]")
		os.Exit(2)
	}
	profileYAML, err := os.ReadFile(*profilePath)
	exitOn(err)
	mapYAML, err := os.ReadFile(*mapPath)
	exitOn(err)

	profile, observed, err := verify.Load(profileYAML, mapYAML)
	exitOn(err)

	report := verify.Verify(profile, observed, *service)
	fmt.Print(report)
	if report.Failed() || (*strict && report.HasWarnings()) {
		os.Exit(1)
	}
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "rc-verify:", err)
		os.Exit(2)
	}
}
