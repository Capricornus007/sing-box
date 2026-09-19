package route

//nolint:unused // marker interface for the adblock-blocked error branch consumed by the Nekobox+ router.go patch stream; kept so the type name is stable across merge re-applies
type adblockBlockedError interface {
	error
	IsAdblockBlocked()
}
