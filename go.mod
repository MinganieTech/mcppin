module github.com/MinganieTech/mcppin

// 1.25.3 is a floor, not a preference. Below it the standard library this
// build signs and verifies with has known ways to be made to do too much work:
// quadratic parsing in encoding/pem and in crypto/x509 name constraints, and
// memory exhaustion in encoding/asn1 - all of them reachable from the PEM a
// -pubkey flag hands to LoadPublicKey, which is attacker-supplied input in a
// tool whose job is to be handed hostile files.
go 1.25.3

require golang.org/x/text v0.41.0
