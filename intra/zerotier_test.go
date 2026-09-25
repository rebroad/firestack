package intra

import (
	"net/netip"
	"testing"
)

func TestZeroTierLocalServiceTarget(t *testing.T) {
	tests := []struct {
		name   string
		target netip.AddrPort
		want   netip.AddrPort
		ok     bool
	}{
		{
			name:   "IPv4 preserves service port",
			target: netip.MustParseAddrPort("192.168.192.7:8022"),
			want:   netip.MustParseAddrPort("127.0.0.1:8022"),
			ok:     true,
		},
		{
			name:   "IPv6 preserves service port",
			target: netip.MustParseAddrPort("[fd00::7]:8022"),
			want:   netip.MustParseAddrPort("[::1]:8022"),
			ok:     true,
		},
		{
			name: "invalid target is unchanged",
			want: netip.AddrPort{},
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := zeroTierLocalServiceTarget(tt.target)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("zeroTierLocalServiceTarget(%v) = (%v, %t), want (%v, %t)",
					tt.target, got, ok, tt.want, tt.ok)
			}
		})
	}
}
