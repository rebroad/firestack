// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestDefaultNetworkTTL(t *testing.T) {
	s := NewNetstack()
	defer s.Close()

	for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		var got tcpip.DefaultTTLOption
		if err := s.NetworkProtocolOption(protocol, &got); err != nil {
			t.Fatalf("read default TTL for protocol %d: %v", protocol, err)
		}
		if got != 64 {
			t.Errorf("default TTL for protocol %d = %d; want 64", protocol, got)
		}
	}
}
