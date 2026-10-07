module github.com/faustbrian/go-identity/risk/valkey

go 1.27.0

require github.com/faustbrian/go-identity/risk v0.0.0-20261007234045-4c91cdd78d20

// Test-only Lua 5.1 execution; native Valkey remains the production runtime.
require github.com/yuin/gopher-lua v1.1.2
