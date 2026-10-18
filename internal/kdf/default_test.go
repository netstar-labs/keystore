package kdf

import "testing"

// Captured at package initialisation, before any test lowers Default for speed.
var defaultAtInit = Default

// Writers stamp Default into every entry they create; it is data in every ring written,
// and it is the cost an attacker who steals a ring file pays per guess. Nothing else
// asserted the production value (every package's TestMain lowers it). The accepted
// bounds are pinned by docs/format.md; this pins the chosen cost.
func TestProductionDefaultCost(t *testing.T) {
	if want := (Cost{Mem: 64 * 1024, Time: 3, Par: 1}); defaultAtInit != want {
		t.Fatalf("kdf.Default = %+v, want %+v (64 MiB, t=3, p=1: docs/format.md \"Encryption\"). "+
			"Lowering it weakens every newly written ring; raising it is a decision (decisions.md), not a drive-by.", defaultAtInit, want)
	}
	if err := (Params{Algo: Algo, Mem: defaultAtInit.Mem, Time: defaultAtInit.Time, Par: defaultAtInit.Par, Salt: make([]byte, SaltLen)}).Check(); err != nil {
		t.Fatalf("the production cost fails its own bounds: %v", err)
	}
}
