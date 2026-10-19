package kdf

import (
	"errors"
	"testing"
)

// shippedDefault is Default as declared, captured at package initialisation before any
// test lowers it for speed.
var shippedDefault = Default

// The accepted ranges are a documented security bound (docs/format.md, scope.md property
// 7). TestCheckBounds expresses them through the exported constants, so a constant that
// drifts moves the test with it; these pin the numbers themselves.
func TestBoundsArePinnedToTheDocumentedNumbers(t *testing.T) {
	salt := make([]byte, SaltLen)
	cases := []struct {
		name string
		p    Params
		ok   bool
	}{
		{"mem min", Params{Algo, 8192, 1, 1, salt}, true},
		{"mem below min", Params{Algo, 8191, 1, 1, salt}, false},
		{"mem max (1 GiB)", Params{Algo, 1048576, 1, 1, salt}, true},
		{"mem above max", Params{Algo, 1048577, 1, 1, salt}, false},
		{"time zero", Params{Algo, 8192, 0, 1, salt}, false},
		{"time max", Params{Algo, 8192, 64, 1, salt}, true},
		{"time above max", Params{Algo, 8192, 65, 1, salt}, false},
		{"par zero", Params{Algo, 8192, 1, 0, salt}, false},
		{"par max", Params{Algo, 8192, 1, 16, salt}, true},
		{"par above max", Params{Algo, 8192, 1, 17, salt}, false},
		{"salt 16", Params{Algo, 8192, 1, 1, make([]byte, 16)}, true},
		{"salt 15", Params{Algo, 8192, 1, 1, make([]byte, 15)}, false},
		{"salt 17", Params{Algo, 8192, 1, 1, make([]byte, 17)}, false},
	}
	for _, c := range cases {
		err := c.p.Check()
		if c.ok && err != nil {
			t.Errorf("%s: Check = %v, want nil", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrParams) {
			t.Errorf("%s: Check = %v, want ErrParams", c.name, err)
		}
	}
}

// New must apply every field of Default, not just some of them.
func TestNewAppliesTheWholeDefaultCost(t *testing.T) {
	saved := Default
	t.Cleanup(func() { Default = saved })
	Default = Cost{Mem: MinMem + 1024, Time: 2, Par: 3}
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if p.Algo != Algo || p.Mem != MinMem+1024 || p.Time != 2 || p.Par != 3 || len(p.Salt) != SaltLen {
		t.Fatalf("New() = %+v, want the Default cost with a %d-byte salt", p, SaltLen)
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	var zero [SaltLen]byte
	if string(p.Salt) == string(zero[:]) {
		t.Fatal("salt is all zero")
	}
}

// The shipped default is the documented cost: 64 MiB, 3 passes, 1 lane (scope.md
// property 1).
func TestShippedDefaultCost(t *testing.T) {
	if shippedDefault != (Cost{Mem: 64 * 1024, Time: 3, Par: 1}) {
		t.Fatalf("Default = %+v, documented cost is 64 MiB / 3 / 1", shippedDefault)
	}
}
