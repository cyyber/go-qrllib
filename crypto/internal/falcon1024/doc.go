// Package falcon1024 implements the Falcon-1024 internals.
//
// The low-level NTRU, FFT, and zint code intentionally keeps some
// reference-style mathematical names for traceability against the Falcon
// reference implementation. Higher-level API, codec, and field helpers use
// more descriptive Go names when that does not obscure the reference flow.
package falcon1024
