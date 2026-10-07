module github.com/faustbrian/go-identity/risk/valkey

go 1.27.0

require github.com/faustbrian/go-identity/risk v0.0.0-20261006162932-0d4d7bb80e54

// Test-only Lua 5.1 execution; native Valkey remains the production runtime.
require github.com/yuin/gopher-lua v1.1.2
