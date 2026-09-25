package expr

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

func TestParseNumber(t *testing.T) {
	cases := []struct {
		in, out string
		err     error
	}{
		{"0", "0", nil}, {"-0", "0", nil}, {"0.000", "0", nil}, {"007", "7", nil},
		{"1.50", "1.5", nil}, {"-1.5e3", "-1500", nil}, {"1E-3", "0.001", nil}, {"+12", "12", nil},
		{".5", "0.5", nil}, {"5.", "5", nil}, {"1e125", "1" + strings.Repeat("0", 125), nil},
		{"12345678901234567890123456789012345678", "12345678901234567890123456789012345678", nil},
		{"123456789012345678901234567890123456789", "", ErrNumberPrecision},
		{"1000000000000000000000000000000000000000000", "1" + strings.Repeat("0", 42), nil}, // trailing zeros aren't precision
		{"1e126", "", ErrNumberOverflow}, {"1e-131", "", ErrNumberUnderflow}, {"1e-130", "0." + strings.Repeat("0", 129) + "1", nil},
		{"", "", ErrNumberSyntax}, {"abc", "", ErrNumberSyntax}, {"1e", "", ErrNumberSyntax}, {" 1", "", ErrNumberSyntax},
		{"1 ", "", ErrNumberSyntax}, {"--1", "", ErrNumberSyntax}, {".", "", ErrNumberSyntax}, {"0x10", "", ErrNumberSyntax},
	}
	for _, c := range cases {
		n, err := ParseNumber(c.in)
		if !errors.Is(err, c.err) {
			t.Errorf("%q: err = %v, want %v", c.in, err, c.err)
			continue
		}
		if err == nil && n.String() != c.out {
			t.Errorf("%q: got %s, want %s", c.in, n.String(), c.out)
		}
	}
}

func mustNum(t *testing.T, s string) Number {
	t.Helper()
	n, err := ParseNumber(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return n
}

func TestNumberAdd(t *testing.T) {
	cases := [][3]string{
		{"0.1", "0.2", "0.3"}, {"1", "-1", "0"}, {"-5.5", "2", "-3.5"},
		{"99999999999999999999999999999999999999", "1", "100000000000000000000000000000000000000"},
		{"1e125", "-1e125", "0"}, {"123.456", "0.544", "124"},
	}
	for _, c := range cases {
		got, err := mustNum(t, c[0]).Add(mustNum(t, c[1]))
		if err != nil || got.String() != c[2] {
			t.Errorf("%s + %s = %s (%v), want %s", c[0], c[1], got.String(), err, c[2])
		}
	}
	if _, err := mustNum(t, "9.9e125").Add(mustNum(t, "9.9e125")); err == nil {
		t.Error("overflow not detected")
	}
}

func ratOf(t *testing.T, n Number) *big.Rat {
	r := new(big.Rat).SetInt(n.Coef)
	p := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs(n.Exp))), nil)
	if n.Exp >= 0 {
		return r.Mul(r, new(big.Rat).SetInt(p))
	}
	return r.Quo(r, new(big.Rat).SetInt(p))
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// TestKeyBytesOrder checks bytewise order == numeric order over edge cases
// and thousands of random numbers across the whole range.
func TestKeyBytesOrder(t *testing.T) {
	fixed := []string{"0", "1", "-1", "0.1", "-0.1", "10", "-10", "12", "123", "-12", "-123", "1.2", "1.23",
		"-1.2", "-1.23", "9.99e125", "-9.99e125", "1e-130", "-1e-130", "99999999999999999999999999999999999999",
		"-99999999999999999999999999999999999999", "0.99999999999999999999999999999999999999", "2", "19", "2.1"}
	var nums []Number
	for _, s := range fixed {
		nums = append(nums, mustNum(t, s))
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 5000; i++ {
		digits := rng.Intn(38) + 1
		var b strings.Builder
		if rng.Intn(2) == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(byte('1' + rng.Intn(9)))
		for j := 1; j < digits; j++ {
			b.WriteByte(byte('0' + rng.Intn(10)))
		}
		exp := rng.Intn(200) - 130
		s := b.String() + "e" + itoa(exp)
		n, err := ParseNumber(s)
		if err != nil {
			continue // out of range: fine
		}
		nums = append(nums, n)
	}
	sort.Slice(nums, func(i, j int) bool { return ratOf(t, nums[i]).Cmp(ratOf(t, nums[j])) < 0 })
	for i := 1; i < len(nums); i++ {
		c := bytes.Compare(nums[i-1].KeyBytes(), nums[i].KeyBytes())
		want := ratOf(t, nums[i-1]).Cmp(ratOf(t, nums[i]))
		if c != want {
			t.Fatalf("order mismatch: %s vs %s: bytes %d, numeric %d", nums[i-1], nums[i], c, want)
		}
		if nums[i-1].Cmp(nums[i]) != want {
			t.Fatalf("Cmp mismatch: %s vs %s", nums[i-1], nums[i])
		}
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }
