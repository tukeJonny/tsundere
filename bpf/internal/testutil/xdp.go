package testutil

type XdpAction uint32

const (
	XDP_ABORTED XdpAction = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func (act XdpAction) String() string {
	switch act {
	case XDP_ABORTED:
		return "XDP_ABORTED"
	case XDP_DROP:
		return "XDP_DROP"
	case XDP_PASS:
		return "XDP_PASS"
	case XDP_TX:
		return "XDP_TX"
	case XDP_REDIRECT:
		return "XDP_REDIRECT"
	default:
		panic("unknown xdp action specified")
	}
}