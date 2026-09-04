package tunnel

type Observer interface {
	ProcessStarted()
	ProcessExited(class string)
	TunnelBytes(dir string, n int)
	ActiveGauge(n int)
}

type NoopObserver struct{}

func (NoopObserver) ProcessStarted()         {}
func (NoopObserver) ProcessExited(string)    {}
func (NoopObserver) TunnelBytes(string, int) {}
func (NoopObserver) ActiveGauge(int)         {}
