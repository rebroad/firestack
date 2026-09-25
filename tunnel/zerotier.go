// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const firstZeroTierNICID tcpip.NICID = 2

var (
	errZeroTierClosed = errors.New("zerotier NIC is closed")
	errZeroTierFrame  = errors.New("invalid zerotier ethernet frame")
)

// zeroTierEndpoint adapts the gVisor link layer to complete Ethernet frames
// exchanged with the ZeroTier Android service.
type zeroTierEndpoint struct {
	mu         sync.RWMutex
	networkID  string
	mtu        uint32
	mac        tcpip.LinkAddress
	bridge     ZeroTierBridge
	dispatcher stack.NetworkDispatcher
	closed     bool
}

var _ stack.LinkEndpoint = (*zeroTierEndpoint)(nil)

func newZeroTierEndpoint(networkID, mac string, mtu uint32, bridge ZeroTierBridge) (*zeroTierEndpoint, error) {
	e := &zeroTierEndpoint{networkID: networkID, mtu: mtu, bridge: bridge}
	if err := e.setMAC(mac); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *zeroTierEndpoint) setMAC(raw string) error {
	m, err := net.ParseMAC(raw)
	if err != nil || len(m) != 6 {
		return fmt.Errorf("invalid zerotier MAC %q", raw)
	}
	e.mu.Lock()
	e.mac = tcpip.LinkAddress(m)
	e.mu.Unlock()
	return nil
}

func (e *zeroTierEndpoint) setBridge(bridge ZeroTierBridge) error {
	if bridge == nil {
		return errors.New("zerotier bridge is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errZeroTierClosed
	}
	e.bridge = bridge
	return nil
}

func (e *zeroTierEndpoint) MTU() uint32           { e.mu.RLock(); defer e.mu.RUnlock(); return e.mtu }
func (e *zeroTierEndpoint) SetMTU(mtu uint32)     { e.mu.Lock(); e.mtu = mtu; e.mu.Unlock() }
func (*zeroTierEndpoint) MaxHeaderLength() uint16 { return header.EthernetMinimumSize }
func (e *zeroTierEndpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mac
}
func (e *zeroTierEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	e.mac = addr
	e.mu.Unlock()
}
func (*zeroTierEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}
func (e *zeroTierEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
}
func (e *zeroTierEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}
func (*zeroTierEndpoint) Wait()                                   {}
func (*zeroTierEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareEther }
func (e *zeroTierEndpoint) SetOnCloseAction(func())               {}

func (e *zeroTierEndpoint) AddHeader(pkt *stack.PacketBuffer) {
	if pkt == nil {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{SrcAddr: pkt.EgressRoute.LocalLinkAddress, DstAddr: pkt.EgressRoute.RemoteLinkAddress, Type: pkt.NetworkProtocolNumber})
}

func (*zeroTierEndpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	if pkt == nil {
		return false
	}
	hdr, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	if !ok {
		return false
	}
	pkt.NetworkProtocolNumber = header.Ethernet(hdr).Type()
	return true
}

func (e *zeroTierEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	bridge, closed := e.bridge, e.closed
	e.mu.RUnlock()
	if closed || bridge == nil {
		return 0, &tcpip.ErrNotPermitted{}
	}
	written := 0
	for _, pkt := range pkts.AsSlice() {
		if pkt == nil {
			continue
		}
		var frame []byte
		for _, part := range pkt.AsSlices() {
			frame = append(frame, part...)
		}
		if len(frame) < header.EthernetMinimumSize {
			return written, &tcpip.ErrMalformedHeader{}
		}
		if err := bridge.WriteFrame(e.networkID, frame); err != nil {
			return written, &tcpip.ErrNoBufferSpace{}
		}
		written++
	}
	return written, nil
}

// injectFrame accepts a whole Ethernet frame from ZeroTier. Parsing the link
// header here mirrors the fd-backed Ethernet dispatcher; the NIC then handles
// ARP or IPv4/IPv6 through its normal network protocol endpoint.
func (e *zeroTierEndpoint) injectFrame(frame []byte) error {
	if len(frame) < header.EthernetMinimumSize {
		return errZeroTierFrame
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	if !e.ParseHeader(pkt) {
		return errZeroTierFrame
	}
	e.mu.RLock()
	dispatcher, closed := e.dispatcher, e.closed
	e.mu.RUnlock()
	if closed {
		return errZeroTierClosed
	}
	if dispatcher == nil {
		return errors.New("zerotier NIC is detached")
	}
	dispatcher.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
	return nil
}

func (e *zeroTierEndpoint) Close() {
	e.mu.Lock()
	e.closed = true
	e.dispatcher = nil
	e.bridge = nil
	e.mu.Unlock()
}
