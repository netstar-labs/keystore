package kdf

import "testing"

// All 16 bytes of the salt are random: across many parameter sets no position is constant
// and no two salts match (a salt with only a couple of random bytes would repeat quickly).
func TestNewSaltIsRandomInEveryByte(t *testing.T) {
	saved := Default
	t.Cleanup(func() { Default = saved })
	Default = Cost{Mem: MinMem, Time: 1, Par: 1}
	const n = 64
	seen := map[string]bool{}
	var distinct [SaltLen]map[byte]bool
	for i := range distinct {
		distinct[i] = map[byte]bool{}
	}
	for i := 0; i < n; i++ {
		p, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(p.Salt)] {
			t.Fatalf("salt %x repeated within %d draws", p.Salt, n)
		}
		seen[string(p.Salt)] = true
		for j, b := range p.Salt {
			distinct[j][b] = true
		}
	}
	for j := range distinct {
		if len(distinct[j]) < 8 { // 64 uniform draws of a byte give ~56 distinct values
			t.Errorf("salt byte %d took only %d distinct values in %d draws", j, len(distinct[j]), n)
		}
	}
}
