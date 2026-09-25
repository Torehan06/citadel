package expr

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Number is a DynamoDB number: an exact decimal of up to 38 significant
// digits with magnitude between 1e-130 and 9.99...e125, or zero.
// Its value is Coef × 10^Exp; Coef has no trailing zeros (normalized), so
// equal numbers have equal representations.
type Number struct {
	Coef *big.Int
	Exp  int
}

const (
	maxDigits = 38
	minExp10  = -130 // smallest magnitude 1e-130
	maxExp10  = 125  // largest magnitude < 1e126
)

var (
	ErrNumberSyntax    = errors.New("invalid number")
	ErrNumberPrecision = errors.New("Attempting to store a number with more than 38 significant digits")
	ErrNumberOverflow  = errors.New("Number overflow. Attempting to store a number with magnitude larger than supported range")
	ErrNumberUnderflow = errors.New("Number underflow. Attempting to store a number with magnitude smaller than supported range")
	bigTen             = big.NewInt(10)
)

// ParseNumber parses DynamoDB's number syntax: optional sign, digits with an
// optional fraction, optional exponent. Leading/trailing spaces are invalid.
func ParseNumber(s string) (Number, error) {
	if s == "" {
		return Number{}, ErrNumberSyntax
	}
	i := 0
	neg := false
	if s[i] == '+' || s[i] == '-' {
		neg = s[i] == '-'
		i++
	}
	var digits strings.Builder
	exp := 0
	sawDigit, sawDot := false, false
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits.WriteByte(c)
			sawDigit = true
			if sawDot {
				exp--
			}
		case c == '.' && !sawDot:
			sawDot = true
		default:
			goto rest
		}
	}
rest:
	if !sawDigit {
		return Number{}, ErrNumberSyntax
	}
	if i < len(s) {
		if s[i] != 'e' && s[i] != 'E' {
			return Number{}, ErrNumberSyntax
		}
		i++
		j := i
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j == len(s) {
			return Number{}, ErrNumberSyntax
		}
		e := 0
		for k := j; k < len(s); k++ {
			if s[k] < '0' || s[k] > '9' {
				return Number{}, ErrNumberSyntax
			}
			if e < 100000 {
				e = e*10 + int(s[k]-'0')
			}
		}
		if s[i] == '-' {
			e = -e
		}
		exp += e
	}
	d := strings.TrimLeft(digits.String(), "0")
	if d == "" {
		return Number{Coef: new(big.Int)}, nil
	}
	// Strip trailing zeros into the exponent.
	t := strings.TrimRight(d, "0")
	exp += len(d) - len(t)
	if len(t) > maxDigits {
		return Number{}, ErrNumberPrecision
	}
	coef, _ := new(big.Int).SetString(t, 10)
	if neg {
		coef.Neg(coef)
	}
	n := Number{Coef: coef, Exp: exp}
	return n, n.check()
}

// adjusted is the exponent of the most significant digit: value = d.ddd × 10^adjusted.
func (n Number) adjusted() int {
	return n.Exp + len(new(big.Int).Abs(n.Coef).String()) - 1
}

func (n Number) check() error {
	if n.Coef.Sign() == 0 {
		return nil
	}
	if len(new(big.Int).Abs(n.Coef).String()) > maxDigits {
		return ErrNumberPrecision
	}
	a := n.adjusted()
	if a > maxExp10 {
		return ErrNumberOverflow
	}
	if a < minExp10 {
		return ErrNumberUnderflow
	}
	return nil
}

func (n Number) normalize() Number {
	if n.Coef.Sign() == 0 {
		return Number{Coef: new(big.Int)}
	}
	c := new(big.Int).Set(n.Coef)
	e := n.Exp
	r := new(big.Int)
	for {
		q, m := new(big.Int).QuoRem(c, bigTen, r)
		if m.Sign() != 0 {
			break
		}
		c, e = q, e+1
	}
	return Number{Coef: c, Exp: e}
}

// Sign returns -1, 0 or +1.
func (n Number) Sign() int { return n.Coef.Sign() }

// Cmp compares two numbers exactly.
func (n Number) Cmp(m Number) int {
	a, b := align(n, m)
	return a.Cmp(b)
}

func align(n, m Number) (*big.Int, *big.Int) {
	a, b := new(big.Int).Set(n.Coef), new(big.Int).Set(m.Coef)
	switch {
	case n.Exp > m.Exp:
		a.Mul(a, new(big.Int).Exp(bigTen, big.NewInt(int64(n.Exp-m.Exp)), nil))
	case m.Exp > n.Exp:
		b.Mul(b, new(big.Int).Exp(bigTen, big.NewInt(int64(m.Exp-n.Exp)), nil))
	}
	return a, b
}

// Add returns n+m, checked against DynamoDB's range and precision.
func (n Number) Add(m Number) (Number, error) {
	a, b := align(n, m)
	r := Number{Coef: a.Add(a, b), Exp: min(n.Exp, m.Exp)}.normalize()
	if err := r.check(); err != nil {
		if errors.Is(err, ErrNumberPrecision) {
			return Number{}, fmt.Errorf("Number overflow. Attempting to store a number with magnitude larger than supported range")
		}
		return Number{}, err
	}
	return r, nil
}

// Neg returns -n.
func (n Number) Neg() Number { return Number{Coef: new(big.Int).Neg(n.Coef), Exp: n.Exp} }

// String renders the number the way DynamoDB returns it: plain decimal
// notation, no exponent, no trailing zeros.
func (n Number) String() string {
	if n.Coef.Sign() == 0 {
		return "0"
	}
	neg := n.Coef.Sign() < 0
	d := new(big.Int).Abs(n.Coef).String()
	var s string
	switch {
	case n.Exp >= 0:
		s = d + strings.Repeat("0", n.Exp)
	case -n.Exp < len(d):
		s = d[:len(d)+n.Exp] + "." + d[len(d)+n.Exp:]
	default:
		s = "0." + strings.Repeat("0", -n.Exp-len(d)) + d
	}
	if neg {
		return "-" + s
	}
	return s
}

// KeyBytes encodes n so that bytewise order equals numeric order:
//
//	0x01 <inverted positive encoding> 0xFF   negative
//	0x02                                     zero
//	0x03 <exponent uint16> <digits+1 ...>    positive
//
// The exponent is that of the most significant digit, biased by 1000.
// Digits are stored as d+1 so no digit byte is 0x00 and, inverted, none is
// 0xFF; the 0xFF terminator then makes a shorter negative sort after a
// longer one with the same prefix (-12 > -123).
func (n Number) KeyBytes() []byte {
	if n.Coef.Sign() == 0 {
		return []byte{0x02}
	}
	d := new(big.Int).Abs(n.Coef).String()
	e := n.adjusted() + 1000
	body := make([]byte, 0, 3+len(d))
	body = append(body, byte(e>>8), byte(e))
	for i := 0; i < len(d); i++ {
		body = append(body, d[i]-'0'+1)
	}
	if n.Coef.Sign() > 0 {
		return append([]byte{0x03}, body...)
	}
	out := make([]byte, 0, len(body)+2)
	out = append(out, 0x01)
	for _, b := range body {
		out = append(out, ^b)
	}
	return append(out, 0xFF)
}
