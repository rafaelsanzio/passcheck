package hibp

// MockClient is a minimal in-memory implementation of the HIBP check for testing.
// It does not call the real API. Use in tests when you need to control breach results.
type MockClient struct {
	// CheckFunc, if set, is used by Check and CheckHash. Return (breached, count, err).
	CheckFunc func(password string) (breached bool, count int, err error)
	// CheckHashFunc, if set, is used by CheckHash. If nil, CheckHash uses CheckFunc with hash as "password".
	CheckHashFunc func(hash string) (breached bool, count int, err error)
}

// Check implements the same semantics as Client.Check using the mock.
func (m *MockClient) Check(password string) (breached bool, count int, err error) {
	if m.CheckFunc != nil {
		return m.CheckFunc(password)
	}
	return false, 0, nil
}

// CheckHash implements the same semantics as Client.CheckHash using the mock.
func (m *MockClient) CheckHash(hash string) (breached bool, count int, err error) {
	if m.CheckHashFunc != nil {
		return m.CheckHashFunc(hash)
	}
	if m.CheckFunc != nil {
		return m.CheckFunc(hash)
	}
	return false, 0, nil
}
