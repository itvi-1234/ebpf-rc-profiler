// Package verify compares a declared Runtime Conditions profile with the
// behavior the eBPF profiler observed, and reports what the profile is missing.
package verify

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ObservedMap is the subset of the profiler's ObservedBehaviors output used here.
type ObservedMap struct {
	Spec struct {
		Behaviors []Behavior `yaml:"behaviors"`
	} `yaml:"spec"`
}

type Behavior struct {
	ID          string `yaml:"id"`
	SourceRef   string `yaml:"sourceRef"`
	Destination struct {
		WorkloadRef string `yaml:"workloadRef"`
	} `yaml:"destination"`
	Facets struct {
		Protocol struct {
			Name     string `yaml:"name"`
			Category string `yaml:"category"`
		} `yaml:"protocol"`
		Network *struct {
			Port       uint16   `yaml:"port"`
			TLS        bool     `yaml:"tls"`
			ServerName string   `yaml:"serverName"`
			EnvNames   []string `yaml:"envNames"`
		} `yaml:"network"`
		Interface *struct {
			HTTP *struct {
				Method string `yaml:"method"`
				Path   string `yaml:"path"`
			} `yaml:"http"`
		} `yaml:"interface"`
	} `yaml:"facets"`
}

// Profile is the subset of a Runtime Conditions profile used here.
type Profile struct {
	Conditions []Condition `yaml:"conditions"`
}

type Condition struct {
	Name      string `yaml:"name"`
	Kind      string `yaml:"kind"`
	Interface struct {
		Type   string `yaml:"type"`
		Engine string `yaml:"engine"`
	} `yaml:"interface"`
	Configuration struct {
		Env          []EnvItem `yaml:"env"`
		Alternatives []struct {
			Env []EnvItem `yaml:"env"`
		} `yaml:"alternatives"`
	} `yaml:"configuration"`
}

type EnvItem struct {
	Name     string `yaml:"name"`
	Property string `yaml:"property"`
}

func (c Condition) envNames() []string {
	var names []string
	for _, item := range c.Configuration.Env {
		names = append(names, item.Name)
	}
	for _, alt := range c.Configuration.Alternatives {
		for _, item := range alt.Env {
			names = append(names, item.Name)
		}
	}
	return names
}

func (c Condition) label() string {
	label := c.Kind
	if c.Interface.Engine != "" {
		label += "/" + c.Interface.Engine
	} else if c.Interface.Type != "" {
		label += "/" + c.Interface.Type
	}
	if c.Name != "" {
		label += " (" + c.Name + ")"
	}
	return label
}

// Observed is one dependency inferred from a behavior.
type Observed struct {
	Kind, Type, Engine string
	Host               string
	Port               uint16
	EnvNames           []string
	Note               string
}

func (o Observed) label() string {
	label := o.Kind
	if o.Engine != "" {
		label += "/" + o.Engine
	} else if o.Type != "" {
		label += "/" + o.Type
	}
	if o.Host != "" {
		label += " " + o.Host
	}
	if o.Port != 0 {
		label += fmt.Sprintf(":%d", o.Port)
	}
	return label
}

// protocolKinds maps a detected protocol to the condition it implies.
var protocolKinds = map[string]struct{ kind, typ, engine string }{
	"postgres":  {"datastore", "relational", "postgres"},
	"mysql":     {"datastore", "relational", "mysql"},
	"mssql":     {"datastore", "relational", "sqlserver"},
	"mongodb":   {"datastore", "document", "mongodb"},
	"redis":     {"cache", "key_value", "redis"},
	"memcached": {"cache", "key_value", "memcached"},
	"kafka":     {"message_bus", "", "kafka"},
	"amqp":      {"message_bus", "", "amqp"},
	"nats":      {"message_bus", "", "nats"},
}

// Observe infers the dependency a behavior represents.
func Observe(b Behavior) (Observed, bool) {
	name := b.Facets.Protocol.Name
	obs := Observed{Host: strings.TrimPrefix(b.Destination.WorkloadRef, "workload:container/")}
	if n := b.Facets.Network; n != nil {
		obs.Port = n.Port
		obs.EnvNames = n.EnvNames
		if n.ServerName != "" {
			obs.Host = n.ServerName
		}
	}

	if known, ok := protocolKinds[name]; ok {
		obs.Kind, obs.Type, obs.Engine = known.kind, known.typ, known.engine
		return obs, true
	}
	switch {
	case name == "tls":
		obs.Kind, obs.Type = "api", "http"
		if obs.Port != 443 && obs.Port != 8443 {
			obs.Note = "TLS service on an unusual port, assumed to be an HTTP API"
		}
		return obs, true
	case strings.HasPrefix(name, "http"), b.Facets.Interface != nil && b.Facets.Interface.HTTP != nil:
		obs.Kind, obs.Type = "api", "http"
		return obs, true
	}
	return Observed{}, false
}

// Level orders findings by how much they should worry the reader.
type Level string

const (
	Error Level = "ERROR" // observed but not declared
	Warn  Level = "WARN"  // declared, but the env wiring does not match
	Info  Level = "INFO"  // declared but not observed in this run
	OK    Level = "OK"
)

type Finding struct {
	Level   Level
	Message string
}

type Report struct {
	Findings []Finding
}

// Failed reports whether the profile is missing something that was observed.
func (r Report) Failed() bool { return r.count(Error) > 0 }

// HasWarnings reports whether any declared condition has mismatched env wiring.
func (r Report) HasWarnings() bool { return r.count(Warn) > 0 }

func (r Report) count(level Level) int {
	n := 0
	for _, f := range r.Findings {
		if f.Level == level {
			n++
		}
	}
	return n
}

func (r Report) String() string {
	var out strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&out, "%-5s %s\n", f.Level, f.Message)
	}
	fmt.Fprintf(&out, "\n%d undeclared, %d env warnings, %d declared but not observed, %d matched\n",
		r.count(Error), r.count(Warn), r.count(Info), r.count(OK))
	return out.String()
}

// Load parses the two YAML documents.
func Load(profileYAML, mapYAML []byte) (Profile, ObservedMap, error) {
	var profile Profile
	var observed ObservedMap
	if err := yaml.Unmarshal(profileYAML, &profile); err != nil {
		return profile, observed, fmt.Errorf("profile: %w", err)
	}
	if err := yaml.Unmarshal(mapYAML, &observed); err != nil {
		return profile, observed, fmt.Errorf("observed map: %w", err)
	}
	return profile, observed, nil
}

// Verify checks that every dependency observed for service (all services when
// empty) is declared in the profile.
func Verify(profile Profile, observed ObservedMap, service string) Report {
	var report Report
	add := func(level Level, format string, args ...any) {
		report.Findings = append(report.Findings, Finding{level, fmt.Sprintf(format, args...)})
	}

	var deps []Observed
	for _, b := range observed.Spec.Behaviors {
		if service != "" && b.SourceRef != "workload:container/"+service {
			continue
		}
		if obs, ok := Observe(b); ok {
			deps = append(deps, obs)
		}
	}
	sort.SliceStable(deps, func(i, j int) bool { return deps[i].label() < deps[j].label() })

	used := make([]bool, len(profile.Conditions))
	for _, dep := range deps {
		var candidates []int
		for i, cond := range profile.Conditions {
			if sameKind(dep, cond) {
				candidates = append(candidates, i)
			}
		}

		// Prefer the condition whose env variables hold this destination's address.
		if i := pickByEnv(profile, candidates, dep.EnvNames); i >= 0 {
			used[i] = true
			add(OK, "%s is declared as %s via %s", dep.label(), profile.Conditions[i].label(), strings.Join(shared(profile.Conditions[i].envNames(), dep.EnvNames), ", "))
			continue
		}

		// With no env link either way, fall back to one unused condition of the same kind.
		if len(dep.EnvNames) == 0 {
			if i := firstUnused(candidates, used); i >= 0 {
				used[i] = true
				add(OK, "%s is declared as %s (env wiring not observed)", dep.label(), profile.Conditions[i].label())
				continue
			}
		}

		if len(candidates) > 0 && len(dep.EnvNames) > 0 {
			i := candidates[0]
			used[i] = true
			add(Warn, "%s: declared as %s, but its env %s does not hold this address (the process used %s)",
				dep.label(), profile.Conditions[i].label(), strings.Join(profile.Conditions[i].envNames(), ", "), strings.Join(dep.EnvNames, ", "))
			continue
		}

		msg := fmt.Sprintf("%s was observed but no condition in the profile declares it", dep.label())
		if dep.Kind == "message_bus" {
			msg += " (message buses need an extension that defines this kind)"
		}
		if dep.Note != "" {
			msg += ": " + dep.Note
		}
		add(Error, "%s", msg)
	}

	for i, cond := range profile.Conditions {
		if !used[i] {
			add(Info, "%s is declared but was not observed in this run (the code path may not have been exercised)", cond.label())
		}
	}
	return report
}

func sameKind(dep Observed, cond Condition) bool {
	if dep.Kind != cond.Kind {
		return false
	}
	if dep.Type != "" && cond.Interface.Type != "" && dep.Type != cond.Interface.Type {
		return false
	}
	if dep.Engine != "" && cond.Interface.Engine != "" && dep.Engine != cond.Interface.Engine {
		return false
	}
	return true
}

func shared(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, name := range b {
		in[name] = true
	}
	var out []string
	for _, name := range a {
		if in[name] {
			out = append(out, name)
		}
	}
	return out
}

func pickByEnv(profile Profile, candidates []int, observedEnv []string) int {
	for _, i := range candidates {
		if len(shared(profile.Conditions[i].envNames(), observedEnv)) > 0 {
			return i
		}
	}
	return -1
}

func firstUnused(candidates []int, used []bool) int {
	for _, i := range candidates {
		if !used[i] {
			return i
		}
	}
	return -1
}
