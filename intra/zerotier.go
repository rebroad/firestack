// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/tunnel"
)

type zeroTierConfig struct {
	mac, addresses, routes string
	bridge                 ZeroTierBridge
}

// zeroTierFlowPath is shared by the TCP and UDP flow handlers. It sends only
// destinations covered by an installed ZeroTier route to NIC 2; selection is
// still gated by the regular flow policy before Dial is called.
type zeroTierFlowPath struct {
	mu  sync.RWMutex
	tun tunnel.Tunnel
}

func zeroTierFlowID(src, dst netip.AddrPort) string {
	return "zerotier:" + src.String() + "=>" + dst.String()
}

func (z *zeroTierFlowPath) setTunnel(tun tunnel.Tunnel) {
	z.mu.Lock()
	z.tun = tun
	z.mu.Unlock()
}

func (z *zeroTierFlowPath) contains(addr netip.Addr) bool {
	z.mu.RLock()
	tun := z.tun
	z.mu.RUnlock()
	return tun != nil && tunnel.HasZeroTierRoute(tun, addr)
}

func (z *zeroTierFlowPath) owns(addr netip.Addr) bool {
	z.mu.RLock()
	tun := z.tun
	z.mu.RUnlock()
	return tun != nil && tunnel.ZeroTierOwnsAddress(tun, addr)
}

// zeroTierLocalServiceTarget maps a connection addressed to this node's
// ZeroTier address to the same service on the device loopback interface. The
// ZeroTier address exists on Firestack's userspace NIC, not on Android's
// kernel interfaces, so dialing it with a protected OS socket would leave the
// device and time out instead of reaching local listeners such as Termux sshd.
func zeroTierLocalServiceTarget(target netip.AddrPort) (netip.AddrPort, bool) {
	if !target.IsValid() {
		return target, false
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if target.Addr().Is6() {
		loopback = netip.MustParseAddr("::1")
	}
	return netip.AddrPortFrom(loopback, target.Port()), true
}

func (z *zeroTierFlowPath) openPacketConn(remote netip.Addr) (net.PacketConn, bool, error) {
	z.mu.RLock()
	tun := z.tun
	z.mu.RUnlock()
	if tun == nil || !tunnel.HasZeroTierRoute(tun, remote) {
		return nil, false, nil
	}
	conn, err := tunnel.DialZeroTierPacketConn(tun, remote)
	return conn, true, err
}

func (z *zeroTierFlowPath) dial(network, remote string) (protect.Conn, bool, error) {
	addrPort, err := netip.ParseAddrPort(remote)
	if err != nil {
		return nil, false, err
	}
	z.mu.RLock()
	tun := z.tun
	z.mu.RUnlock()
	if tun == nil || !tunnel.HasZeroTierRoute(tun, addrPort.Addr()) {
		return nil, false, nil
	}
	conn, err := tunnel.DialZeroTier(tun, network, remote)
	return conn, true, err
}

func zeroTierDirectProxy(px ipn.Proxy, via string) bool {
	if px == nil || len(via) != 0 {
		return false
	}
	return px.ID() == ipn.Base || px.ID() == ipn.Exit
}

func (t *rtunnel) ConfigureZeroTier(networkID, mac, addressesCSV, routesCSV string, bridge ZeroTierBridge) error {
	if t.closed.Load() {
		return errClosed
	}
	if bridge == nil {
		return errors.New("zerotier bridge is nil")
	}
	t.ztConfigMu.Lock()
	defer t.ztConfigMu.Unlock()
	current := t.t.Load()
	if err := tunnel.ConfigureZeroTier(current, networkID, mac, addressesCSV, routesCSV, zeroTierBridgeAdapter{bridge}); err != nil {
		return err
	}
	if t.ztConfig == nil {
		t.ztConfig = make(map[string]zeroTierConfig)
	}
	t.ztConfig[networkID] = zeroTierConfig{mac: mac, addresses: addressesCSV, routes: routesCSV, bridge: bridge}
	return nil
}

func (t *rtunnel) InjectZeroTierFrame(networkID string, frame []byte) error {
	if t.closed.Load() {
		return errClosed
	}
	return tunnel.InjectZeroTierFrame(t.t.Load(), networkID, frame)
}

func (t *rtunnel) ClearZeroTier(networkID string) error {
	t.ztConfigMu.Lock()
	defer t.ztConfigMu.Unlock()
	if err := tunnel.ClearZeroTier(t.t.Load(), networkID); err != nil {
		return err
	}
	delete(t.ztConfig, networkID)
	return nil
}
