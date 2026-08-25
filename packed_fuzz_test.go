package hdrhistogram

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzPackedDecodeHostile: DecodePacked must never panic on arbitrary bytes, and
// any successfully-decoded histogram must survive query + re-encode + re-decode.
func FuzzPackedDecodeHostile(f *testing.F) {
	p := NewPacked(1, 3600000000, 3)
	p.RecordValue(1000)
	p.RecordValues(2000000, 500000) // force a wider count width in the corpus
	if enc, err := p.Encode(); err == nil {
		f.Add(enc)
	}
	f.Add([]byte("not base64!!"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		hp, err := DecodePacked(data)
		if err != nil {
			return
		}
		_ = hp.TotalCount()
		_ = hp.Min()
		_ = hp.Max()
		_ = hp.ValueAtPercentile(0)
		_ = hp.ValueAtPercentile(50)
		_ = hp.ValueAtPercentile(100)
		_ = hp.ValueAtPercentilesSlice([]float64{0, 99, 99.9, 100})
		re, err := hp.Encode()
		if err != nil {
			t.Fatalf("re-encode of a decoded histogram failed: %v", err)
		}
		hp2, err := DecodePacked(re)
		if err != nil {
			t.Fatalf("re-decode of our own stream failed: %v", err)
		}
		if hp2.TotalCount() != hp.TotalCount() {
			t.Fatalf("total drifted across re-encode: %d != %d", hp2.TotalCount(), hp.TotalCount())
		}
	})
}

// FuzzPackedDifferential: interpret the input as 16-byte (value, count) records,
// apply the same stream to dense and packed, and assert full parity + a
// byte-identical V2 encode.
func FuzzPackedDifferential(f *testing.F) {
	seed := make([]byte, 0, 32)
	seed = binary.BigEndian.AppendUint64(seed, 1000)
	seed = binary.BigEndian.AppendUint64(seed, 1)
	seed = binary.BigEndian.AppendUint64(seed, 6147)
	seed = binary.BigEndian.AppendUint64(seed, 70000)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		d := New(1, 3600000000, 3)
		p := NewPacked(1, 3600000000, 3)
		for i := 0; i+16 <= len(data); i += 16 {
			v := int64(binary.BigEndian.Uint64(data[i:]))
			c := int64(binary.BigEndian.Uint64(data[i+8:]))
			if v < 0 {
				v = -v
			}
			v = v%3600000000 + 1
			if c < 0 {
				c = -c
			}
			c = c%100000 + 1
			if err := d.RecordValues(v, c); err != nil {
				continue
			}
			if err := p.RecordValues(v, c); err != nil {
				t.Fatalf("packed rejected a value dense accepted: v=%d c=%d: %v", v, c, err)
			}
		}
		if d.TotalCount() != p.TotalCount() {
			t.Fatalf("total %d != %d", d.TotalCount(), p.TotalCount())
		}
		if d.Min() != p.Min() || d.Max() != p.Max() {
			t.Fatalf("min/max mismatch: dense (%d,%d) packed (%d,%d)", d.Min(), d.Max(), p.Min(), p.Max())
		}
		for _, pc := range []float64{0, 25, 50, 90, 99, 99.9, 100} {
			if d.ValueAtPercentile(pc) != p.ValueAtPercentile(pc) {
				t.Fatalf("p%.4g dense %d != packed %d", pc, d.ValueAtPercentile(pc), p.ValueAtPercentile(pc))
			}
		}
		de, err := d.Encode(V2CompressedEncodingCookieBase)
		if err != nil {
			t.Fatal(err)
		}
		pe, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(de, pe) {
			t.Fatalf("encode mismatch (dense %d bytes, packed %d bytes)", len(de), len(pe))
		}
	})
}
