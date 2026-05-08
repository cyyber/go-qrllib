package falcon1024

// modP helpers implement arithmetic over Falcon's auxiliary 31-bit primes used
// by the NTRU/CRT solver. They are intentionally separate from the field
// helpers, which operate modulo the fixed Falcon field modulus q.

func modPSet(x int32, p uint32) uint32 {
	w := uint32(x)
	w += p & -(w >> 31)
	return w
}

func modPNorm(x, p uint32) int32 {
	w := x - (p & -(((p >> 1) - x) >> 31))
	return int32(w)
}

func modPAdd(a, b, p uint32) uint32 {
	d := a + b - p
	d += p & -(d >> 31)
	return d
}

func modPSub(a, b, p uint32) uint32 {
	d := a - b
	d += p & -(d >> 31)
	return d
}

func modPHalf(a, p uint32) uint32 {
	return (a + (p & -(a & 1))) >> 1
}

func modPMontyMul(a, b, p, p0i uint32) uint32 {
	z := uint64(a) * uint64(b)
	w := (uint32(z) * p0i) & 0x7FFFFFFF
	z = (z + uint64(w)*uint64(p)) >> 31
	d := uint32(z) - p
	d += p & -(d >> 31)
	return d
}

func modPNInv31(p uint32) uint32 {
	y := uint32(2 - p)
	y *= 2 - p*y
	y *= 2 - p*y
	y *= 2 - p*y
	y *= 2 - p*y
	return 0x7FFFFFFF & -y
}

func modPR(p uint32) uint32 {
	return ((uint32(1) << 31) - p)
}

func modPR2(p, p0i uint32) uint32 {
	z := modPR(p)
	z = modPAdd(z, z, p)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	return modPHalf(z, p)
}

func modPRx(x int, p, p0i, r2 uint32) uint32 {
	x--
	r := r2
	z := modPR(p)
	for i := 0; (1 << i) <= x; i++ {
		if x&(1<<i) != 0 {
			z = modPMontyMul(z, r, p, p0i)
		}
		r = modPMontyMul(r, r, p, p0i)
	}
	return z
}

func modPDiv(a, b, p, p0i, r uint32) uint32 {
	e := p - 2
	z := r
	for i := 30; i >= 0; i-- {
		z = modPMontyMul(z, z, p, p0i)
		z2 := modPMontyMul(z, b, p, p0i)
		z ^= (z ^ z2) & -((e >> i) & 1)
	}
	z = modPMontyMul(z, 1, p, p0i)
	return modPMontyMul(a, z, p, p0i)
}

func modPMkgm2(gm, igm []uint32, primitiveRoot, p, p0i uint32) {
	nn := len(gm)
	if len(igm) < nn {
		panic("falcon1024: invalid modp root table")
	}
	logn := 0
	for (1 << logn) < nn {
		logn++
	}

	r2 := modPR2(p, p0i)
	g := modPMontyMul(primitiveRoot, r2, p, p0i)
	for i := nn; i < 1<<10; i <<= 1 {
		g = modPMontyMul(g, g, p, p0i)
	}

	ig := modPDiv(r2, g, p, p0i, modPR(p))
	x1 := modPR(p)
	x2 := modPR(p)
	for i := range nn {
		j := bitReverse10(uint32(i)) >> (10 - logn)
		gm[j] = x1
		igm[j] = x2
		x1 = modPMontyMul(x1, g, p, p0i)
		x2 = modPMontyMul(x2, ig, p, p0i)
	}
}

func modPNTT2(a, gm []uint32, p, p0i uint32) {
	modPNTT2Ext(a, 1, gm, p, p0i)
}

func modPNTT2Ext(a []uint32, stride int, gm []uint32, p, p0i uint32) {
	nn := (len(a) + stride - 1) / stride
	t := nn
	for m := 1; m < nn; m <<= 1 {
		ht := t >> 1
		for i, j1 := 0, 0; i < m; i, j1 = i+1, j1+t {
			s := gm[m+i]
			j2 := j1 + ht
			for j := j1; j < j2; j++ {
				jx := j * stride
				jy := (j + ht) * stride
				u := a[jx]
				v := modPMontyMul(a[jy], s, p, p0i)
				a[jx] = modPAdd(u, v, p)
				a[jy] = modPSub(u, v, p)
			}
		}
		t = ht
	}
}

func modPINTT2(a, igm []uint32, p, p0i uint32) {
	modPINTT2Ext(a, 1, igm, p, p0i)
}

func modPINTT2Ext(a []uint32, stride int, igm []uint32, p, p0i uint32) {
	nn := (len(a) + stride - 1) / stride
	t := 1
	for m := nn; m > 1; m >>= 1 {
		hm := m >> 1
		dt := t << 1
		for i, j1 := 0, 0; i < hm; i, j1 = i+1, j1+dt {
			s := igm[hm+i]
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				jx := j * stride
				jy := (j + t) * stride
				u := a[jx]
				v := a[jy]
				a[jx] = modPAdd(u, v, p)
				a[jy] = modPMontyMul(modPSub(u, v, p), s, p, p0i)
			}
		}
		t = dt
	}

	ni := modPR(p)
	for m := nn; m > 1; m >>= 1 {
		ni = modPHalf(ni, p)
	}
	for i := range nn {
		j := i * stride
		a[j] = modPMontyMul(a[j], ni, p, p0i)
	}
}

func modPPolyRecRes(f []uint32, logn int, p, p0i, r2 uint32) {
	hn := 1 << (logn - 1)
	for i := range hn {
		f[i] = modPMontyMul(modPMontyMul(f[i<<1], f[(i<<1)+1], p, p0i), r2, p, p0i)
	}
}

func bitReverse10(x uint32) uint32 {
	var r uint32
	for range 10 {
		r = (r << 1) | (x & 1)
		x >>= 1
	}
	return r
}
