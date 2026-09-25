// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tunnel

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/celzero/firestack/intra/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type frameRecorder struct{ frames chan []byte }

func (r *frameRecorder) WriteFrame(_ string, frame []byte) error {
	r.frames <- append([]byte(nil), frame...)
	return nil
}

type packetRecorder struct {
	protocol tcpip.NetworkProtocolNumber
	called   bool
}

func (r *packetRecorder) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	r.protocol, r.called = protocol, true
}
func (*packetRecorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestInjectZeroTierFrameParsesEthernetProtocol(t *testing.T) {
	ep, err := newZeroTierEndpoint("test", "02:00:00:00:00:02", 1400, &frameRecorder{frames: make(chan []byte, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &packetRecorder{}
	ep.Attach(dispatcher)
	frame := make([]byte, header.EthernetMinimumSize+20)
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, 9}),
		DstAddr: tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, 2}),
		Type:    header.IPv4ProtocolNumber,
	})
	if err := ep.injectFrame(frame); err != nil {
		t.Fatal(err)
	}
	if !dispatcher.called || dispatcher.protocol != ipv4.ProtocolNumber {
		t.Fatalf("injected protocol = %d, called=%t; want IPv4", dispatcher.protocol, dispatcher.called)
	}
	if err := ep.injectFrame(frame[:header.EthernetMinimumSize-1]); err == nil {
		t.Fatal("short Ethernet frame accepted")
	}
}

func TestParseZeroTierRouteSyntax(t *testing.T) {
	routes, err := parseRoutes("10.9.0.0/16=10.8.0.1@42, ::/0@7")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].metric != 42 || routes[0].gateway != netip.MustParseAddr("10.8.0.1") || routes[1].metric != 7 || routes[1].prefix.Bits() != 0 {
		t.Fatalf("parsed routes = %#v", routes)
	}
}

func TestParseZeroTierAddressesPreservesHostBits(t *testing.T) {
	addresses, err := parsePrefixes("192.168.192.7/24, fd00::7/64")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.192.7/24"),
		netip.MustParsePrefix("fd00::7/64"),
	}
	if len(addresses) != len(want) {
		t.Fatalf("parsed addresses = %v; want %v", addresses, want)
	}
	for i := range want {
		if addresses[i] != want[i] {
			t.Fatalf("address %d = %v; want assigned host address %v", i, addresses[i], want[i])
		}
	}
}

func TestZeroTierOwnsAddressUsesAssignedHost(t *testing.T) {
	gt := &gtunnel{ztNets: map[string]*zeroTierNetwork{
		"network": {nicID: 2, addresses: []netip.Prefix{netip.MustParsePrefix("192.168.192.7/24")}},
	}}
	if !ZeroTierOwnsAddress(gt, netip.MustParseAddr("192.168.192.7")) {
		t.Fatal("assigned ZeroTier address was not recognized")
	}
	if ZeroTierOwnsAddress(gt, netip.MustParseAddr("192.168.192.5")) {
		t.Fatal("peer address was incorrectly recognized as local")
	}
	if nic, ok := ZeroTierNICForAddress(gt, netip.MustParseAddr("192.168.192.5")); !ok || nic != 2 {
		t.Fatalf("assigned subnet route selected NIC %d, %t; want NIC 2", nic, ok)
	}
}

func TestZeroTierRouteSelectionUsesPrefixMetricAndNetworkID(t *testing.T) {
	gt := &gtunnel{stack: netstack.NewNetstack(), ztNets: map[string]*zeroTierNetwork{}}
	for i, id := range []string{"b-network", "a-network", "specific"} {
		nic := tcpip.NICID(i + 2)
		gt.ztNets[id] = &zeroTierNetwork{nicID: nic, routes: []zeroTierRoute{
			{metric: []uint32{5, 5, 100}[i], networkID: id, prefix: []netip.Prefix{
				netip.MustParsePrefix("10.20.0.0/16"),
				netip.MustParsePrefix("10.20.0.0/16"),
				netip.MustParsePrefix("10.20.4.0/24"),
			}[i]},
		}}
	}
	got, ok := ZeroTierNICForAddress(gt, netip.MustParseAddr("10.20.4.9"))
	if !ok || got != 4 { // longest prefix wins, even with a larger metric
		t.Fatalf("specific-prefix NIC = %d, %t; want 4, true", got, ok)
	}
	got, ok = ZeroTierNICForAddress(gt, netip.MustParseAddr("10.20.9.9"))
	if !ok || got != 3 { // equal prefix and metric: lexical network ID wins
		t.Fatalf("tie-break NIC = %d, %t; want 3, true", got, ok)
	}
}

func TestZeroTierUDPFlowEmitsRoutedEthernetFrame(t *testing.T) {
	const (
		nwid       = "0123456789abcdef"
		localMAC   = "02:00:00:00:00:02"
		remoteMAC  = "02:00:00:00:00:09"
		remoteAddr = "10.8.0.9:5353"
	)
	s := netstack.NewNetstack()
	defer s.Close()
	bridge := &frameRecorder{frames: make(chan []byte, 4)}
	ep, err := newZeroTierEndpoint(nwid, localMAC, 1400, bridge)
	if err != nil {
		t.Fatal(err)
	}
	const nic tcpip.NICID = 2
	if err := s.CreateNIC(nic, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpoofing(nic, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPromiscuousMode(nic, true); err != nil {
		t.Fatal(err)
	}
	local := tcpip.AddrFrom4([4]byte{10, 8, 0, 2})
	if err := s.AddProtocolAddress(nic, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: local, PrefixLen: 24},
	}, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint}); err != nil {
		t.Fatal(err)
	}
	remote := tcpip.AddrFrom4([4]byte{10, 8, 0, 9})
	remoteMACBytes, err := net.ParseMAC(remoteMAC)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddStaticNeighbor(nic, ipv4.ProtocolNumber, remote, tcpip.LinkAddress(remoteMACBytes)); err != nil {
		t.Fatal(err)
	}
	subnet, err := netip.ParsePrefix("10.8.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	gt := &gtunnel{
		stack: s,
		ztNets: map[string]*zeroTierNetwork{nwid: {
			nicID:  nic,
			routes: []zeroTierRoute{{networkID: nwid, prefix: subnet}},
		}},
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: tcpipSubnet(subnet), NIC: nic}})

	conn, err := DialZeroTier(gt, "udp", remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zerotier-path")); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-bridge.frames:
		if len(frame) < header.EthernetMinimumSize+20+8+len("zerotier-path") {
			t.Fatalf("outbound frame too short: %d", len(frame))
		}
		localMACBytes, _ := net.ParseMAC(localMAC)
		if !bytes.Equal(frame[:6], remoteMACBytes) || !bytes.Equal(frame[6:12], localMACBytes) {
			t.Fatalf("Ethernet addresses: dst=%x src=%x", frame[:6], frame[6:12])
		}
		if got := header.Ethernet(frame).Type(); got != header.IPv4ProtocolNumber {
			t.Fatalf("Ethernet type = %#x, want IPv4", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Ethernet frame emitted by ZeroTier UDP route")
	}
}

func tcpipSubnet(p netip.Prefix) tcpip.Subnet {
	addr := tcpip.AddrFrom4(p.Addr().As4())
	mask := tcpip.MaskFromBytes([]byte{255, 255, 255, 0})
	subnet, err := tcpip.NewSubnet(addr, mask)
	if err != nil {
		panic(err)
	}
	return subnet
}
