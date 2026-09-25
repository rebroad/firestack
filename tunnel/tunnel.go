// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Tunnel represents a session on a TUN device.
type Tunnel interface {
	// IsConnected indicates whether the tunnel is in a connected state.
	IsConnected() bool
	// Disconnect disconnects the tunnel.
	Disconnect()
	// Enabled checks if the tunnel is up and running.
	Enabled() bool
	// Mtu returns the current MTU of the tunnel (tun MTU).
	Mtu() int32
	// Creates a new link using fd (tun device).
	SetLinkAndRoutes(fd, tunmtu, engine int) error
	// Unsets existing link and closes the fd (tun device).
	Unlink() error
	// Set or unset the pcap sink
	SetPcap(fpcap string) error
	// NIC, IP, TCP, UDP, and ICMP stats.
	Stat() (*x.NetStat, error)
}

// ZeroTierBridge passes complete Ethernet frames to the Android ZeroTier node.
type ZeroTierBridge interface {
	WriteFrame(networkID string, frame []byte) error
}

type gtunnel struct {
	ctx    context.Context
	done   context.CancelFunc
	stack  *stack.Stack              // a tcpip stack
	ep     netstack.SeamlessEndpoint // endpoint for the stack
	sid    atomic.Int64              // session id (almost always tunnel fd)
	hdl    netstack.GConnHandler     // tcp, udp, and icmp handlers
	pcapio *pcapsink                 // pcap output, if any
	closed atomic.Bool               // open/close?
	once   sync.Once
	ztMu   sync.Mutex
	ztNets map[string]*zeroTierNetwork
}

type zeroTierRoute struct {
	route     tcpip.Route
	metric    uint32
	networkID string
	prefix    netip.Prefix
}
type zeroTierNetwork struct {
	nicID     tcpip.NICID
	ep        *zeroTierEndpoint
	addresses []netip.Prefix
	routes    []zeroTierRoute
}

var _ Tunnel = (*gtunnel)(nil)

var (
	errInvalidTunFd = errors.New("invalid tun fd")
	zerowriter      = &nowrite{}
)

func (t *gtunnel) Mtu() int32 {
	if t.IsConnected() {
		// return int32(t.stack.NICInfo()[0].MTU)
		return int32(t.ep.MTU())
	}
	return -1
}

func (t *gtunnel) waitForEndpoint() {
	const maxchecks = 5
	const betweenChecks = 3 * time.Second
	const uptimeThreshold = 3 * time.Second

	waitStart := time.Now()
	i := 0

	defer func() {
		t.done() // cancel current context, if not already done
		log.I("tun: waiter: done; #%d, %s", i, core.FmtTimeAsPeriod(waitStart))
	}()

	for i < maxchecks && !t.closed.Load() {
		// wait a bit to let the endpoint settle
		time.Sleep(betweenChecks)
		start := time.Now()
		runid := "g." + strconv.Itoa(i)

		select {
		case <-t.ctx.Done():
			t.Disconnect() // may already be disconnected
			log.D("tun: waiter: ctx done; #%d", i)
			return
		case <-core.SigFin(runid, t.ep.Wait): // wait until endpoint closes
			log.D("tun: waiter: endpoint not running; #%d", i)
		}

		// if the endpoint was up for more than uptimeThreshold,
		// reset the counter and do another set of maxchecks
		// as a new endpoint may have been created in between
		// see: SetLink -> t.ep.Swap
		if uptime := time.Since(start); uptime >= uptimeThreshold {
			i = 0 // good ep just closed, restart maxchecks
		} else { // no endpoint / bad endpoint still closed
			// ep.Wait was super quick, and it is possible
			// no endpoint will show up in the next few checks
			// but if it does, then i is reset to 0 anyway
			i++
		}
	}
	if !t.closed.Load() {
		// the endpoint closed without a Disconnect, this may happen
		// in cases where a panic was recovered and endpoint was
		// closed without a t.ep.Swap or t.stack.Destroy
		log.U(fmt.Sprintf("Deactivated! Down after %s", core.FmtTimeAsPeriod(waitStart)))
		// todo: disconnect parent tunnel
		t.Disconnect() // may already be disconnected
	}
}

func (t *gtunnel) Disconnect() {
	defer core.Recover(core.Exit11, "g.Disconnect")

	// no core.Recover here as the tunnel is disconnecting anyway
	t.once.Do(func() {
		t.closed.Store(true)
		// go t.Unlink() // may block? takes more time?
		t.ztMu.Lock()
		for _, network := range t.ztNets {
			network.ep.Close()
		}
		t.ztMu.Unlock()
		t.stack.Destroy()
		log.I("tun: %d netstack closed", t.sid.Load())
	})
}

func (t *gtunnel) Enabled() bool {
	s := t.stack

	// nic may be down even if tunnel is up, when SetLink is in between
	// removing existing nic and creating a new one.
	return s != nil && s.CheckNIC(settings.NICID)
}

func (t *gtunnel) IsConnected() bool {
	return !t.closed.Load()
}

// fd must be non-blocking.
func NewGTunnel(pctx context.Context, fd, mtu int, l3 string, hdl netstack.GConnHandler) (t *gtunnel, rev netstack.GConnHandler, err error) {
	myfd, err := maybeDup(fd) // tunnel will own myfd
	if err != nil {
		return nil, nil, err
	}

	ctx, done := context.WithCancel(pctx)

	sink := newSink(ctx)
	stack := netstack.NewNetstack() // always dual-stack
	// NewEndpoint takes ownership of myfd; closes it on errors
	ep, eerr := netstack.NewEndpoint(myfd, mtu, sink)
	if eerr != nil {
		done()
		return nil, nil, eerr
	}

	var nic tcpip.NICID
	if l3 != settings.IP46 {
		l3 = settings.IP46 // always dual-stack
		log.W("tun: new netstack(%d) l3 is %s needed %s", fd, l3, settings.IP46)
	}
	// set route before calling Up
	netstack.Route(stack, l3)
	// Enabled() may temporarily return false when Up() is in progress.
	if nic, err = netstack.Up(stack, ep, hdl); err != nil { // attach new endpoint
		done()
		return nil, nil, err
	}

	rev = netstack.NewReverseGConnHandler(ctx, stack, nic, ep, hdl)

	log.I("tun: new netstack(%d) up; fd(%d=>%d), mtu(%d)", nic, fd, myfd, mtu)

	t = &gtunnel{
		ctx:    ctx,
		done:   done,
		stack:  stack,
		ep:     ep,
		hdl:    hdl,
		pcapio: sink,
		closed: atomic.Bool{},
		once:   sync.Once{},
	}
	t.sid.Store(int64(fd))          // fd is the og tun device
	t.setRoute(settings.Engine(l3)) // sets happy eyeballs
	core.Go("tun.awaiter", t.waitForEndpoint)

	return
}

func (t *gtunnel) SetPcap(fp string) error {
	defer core.Recover(core.Exit11, "g.SetPcap")

	pcap := t.pcapio

	ignored := pcap.recycle() // close any existing pcap sink
	if len(fp) == 0 {
		log.I("tun: pcap closed (ignored-err? %v)", ignored)
		return nil // nothing else to do; pcap closed
	} else if len(fp) == 1 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		ok := pcap.log(true)
		log.I("tun: pcap(%s)/log(%t)", fp, ok)
		return nil // fdbased will write to stdout
	} else if fout, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err == nil {
		ignored = pcap.file(fout) // attach
		log.I("tun: pcap(%s)/file(%v) (ignored-err? %v)", fp, fout, ignored)
		return nil // sniffer will write to fout
	} else {
		log.E("tun: pcap(%s); (err? %v)", fp, err)
		return err // no pcap
	}
}

func (t *gtunnel) Unlink() error {
	defer core.Recover(core.Exit11, "g.Unlink")

	return t.ep.Dispose()
}

func (t *gtunnel) SetLinkAndRoutes(fd, mtu, engine int) (err error) {
	defer core.Recover(core.Exit11, "g.SetLinkAndRoutes")

	if err := t.setLink(fd, mtu); err != nil {
		return err
	}
	return t.setRoute(engine)
}

func (t *gtunnel) setLink(fd, mtu int) (err error) {
	defer func() {
		if err != nil {
			t.sid.Store(-1) // reset sid
		} else {
			t.sid.Store(int64(fd)) // set sid to fd
		}
	}()

	myfd, err := maybeDup(fd) // endpoint owns myfd
	if err != nil {
		log.E("tun: new link; err %v", err)
		return err
	}

	err = t.ep.Swap(myfd, mtu) // swap fd and mtu

	log.I("tun: new link, fd(%d => %d) mtu(%d); err? %v", fd, myfd, mtu, err)
	return err
}

func (t *gtunnel) setRoute(engine int) error {
	t.ztMu.Lock()
	routes := t.zeroTierRoutesLocked()
	t.ztMu.Unlock()
	t.stack.SetRouteTable(routes)
	log.I("tun: new route; (no-op) got %s but set %s; doing happy eyeballs? %t",
		settings.L3(engine), settings.IP46, settings.HappyEyeballs.Load())
	return nil
}

func (t *gtunnel) configureZeroTier(networkID, mac, addressesCSV, routesCSV string, bridge ZeroTierBridge) error {
	t.ztMu.Lock()
	defer t.ztMu.Unlock()
	if t.closed.Load() {
		return errors.New("tunnel closed")
	}
	if strings.TrimSpace(networkID) == "" {
		return errors.New("zerotier network id is empty")
	}
	if bridge == nil {
		return errors.New("zerotier bridge is nil")
	}
	addresses, err := parsePrefixes(addressesCSV)
	if err != nil {
		return err
	}
	routes, err := parseRoutes(routesCSV)
	if err != nil {
		return err
	}
	network := t.ztNets[networkID]
	if network == nil {
		nicID := t.nextZeroTierNICIDLocked()
		if nicID == 0 {
			return errors.New("no free NIC id for ZeroTier")
		}
		ep, err := newZeroTierEndpoint(networkID, mac, uint32(t.ep.MTU()), bridge)
		if err != nil {
			return err
		}
		if err := t.stack.CreateNIC(nicID, ep); err != nil {
			ep.Close()
			return errors.New(err.String())
		}
		if err := t.stack.SetSpoofing(nicID, true); err != nil {
			t.stack.RemoveNIC(nicID)
			ep.Close()
			return errors.New(err.String())
		}
		if err := t.stack.SetPromiscuousMode(nicID, true); err != nil {
			t.stack.RemoveNIC(nicID)
			ep.Close()
			return errors.New(err.String())
		}
		network = &zeroTierNetwork{nicID: nicID, ep: ep}
		if t.ztNets == nil {
			t.ztNets = make(map[string]*zeroTierNetwork)
		}
		t.ztNets[networkID] = network
	} else if err := network.ep.setMAC(mac); err != nil {
		return err
	}
	if err := t.stack.SetNICAddress(network.nicID, network.ep.LinkAddress()); err != nil {
		return errors.New(err.String())
	}
	if err := network.ep.setBridge(bridge); err != nil {
		return err
	}
	if err := replaceZeroTierAddresses(t.stack, network.nicID, addresses); err != nil {
		return err
	}
	ztRoutes, err := routesForNIC(routes, network.nicID)
	if err != nil {
		return err
	}
	network.addresses = addresses
	network.routes = make([]zeroTierRoute, 0, len(ztRoutes))
	for i, r := range ztRoutes {
		network.routes = append(network.routes, zeroTierRoute{route: r, metric: routes[i].metric, networkID: networkID, prefix: routes[i].prefix})
	}
	t.stack.SetRouteTable(t.zeroTierRoutesLocked())
	return nil
}

func (t *gtunnel) nextZeroTierNICIDLocked() tcpip.NICID {
	for id := firstZeroTierNICID; id < tcpip.NICID(0xffff); id++ {
		if !t.stack.CheckNIC(id) {
			return id
		}
	}
	return 0
}

func (t *gtunnel) zeroTierRoutesLocked() []tcpip.Route {
	var entries []zeroTierRoute
	default4, default6 := false, false
	for _, network := range t.ztNets {
		for _, route := range network.routes {
			entries = append(entries, route)
			if route.prefix.Bits() == 0 && route.prefix.Addr().Is4() {
				default4 = true
			}
			if route.prefix.Bits() == 0 && route.prefix.Addr().Is6() {
				default6 = true
			}
		}
		for _, addr := range network.addresses {
			routes, err := routesForNIC([]routeSpec{{prefix: addr}}, network.nicID)
			if err == nil {
				entries = append(entries, zeroTierRoute{route: routes[0], networkID: networkIDFromNic(t.ztNets, network.nicID), prefix: addr})
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].prefix.Bits() != entries[j].prefix.Bits() {
			return entries[i].prefix.Bits() > entries[j].prefix.Bits()
		}
		if entries[i].metric != entries[j].metric {
			return entries[i].metric < entries[j].metric
		}
		return entries[i].networkID < entries[j].networkID
	})
	base := netstack.DefaultRoutes()
	if default4 {
		base = removeDefaultRoute(base, header.IPv4EmptySubnet)
	}
	if default6 {
		base = removeDefaultRoute(base, header.IPv6EmptySubnet)
	}
	for _, entry := range entries {
		base = append(base, entry.route)
	}
	return base
}

func networkIDFromNic(nets map[string]*zeroTierNetwork, nic tcpip.NICID) string {
	for id, network := range nets {
		if network.nicID == nic {
			return id
		}
	}
	return ""
}

func removeDefaultRoute(routes []tcpip.Route, dst tcpip.Subnet) []tcpip.Route {
	for i := range routes {
		if routes[i].Destination == dst {
			return append(routes[:i], routes[i+1:]...)
		}
	}
	return routes
}

func (t *gtunnel) injectZeroTierFrame(networkID string, frame []byte) error {
	t.ztMu.Lock()
	network := t.ztNets[networkID]
	t.ztMu.Unlock()
	if network == nil {
		return errors.New("zerotier network is not configured")
	}
	return network.ep.injectFrame(frame)
}

func (t *gtunnel) clearZeroTier(networkID string) error {
	t.ztMu.Lock()
	defer t.ztMu.Unlock()
	network := t.ztNets[networkID]
	if network == nil {
		return nil
	}
	delete(t.ztNets, networkID)
	t.stack.SetRouteTable(t.zeroTierRoutesLocked())
	if err := t.stack.RemoveNIC(network.nicID); err != nil {
		return errors.New(err.String())
	}
	network.ep.Close()
	return nil
}

// ConfigureZeroTier configures the private secondary NIC without adding SDK
// types or gVisor types to Intra's public gomobile interface.
func ConfigureZeroTier(t Tunnel, networkID, mac, addressesCSV, routesCSV string, bridge ZeroTierBridge) error {
	gt, ok := t.(*gtunnel)
	if !ok {
		return errors.New("tunnel does not support ZeroTier")
	}
	return gt.configureZeroTier(networkID, mac, addressesCSV, routesCSV, bridge)
}

func InjectZeroTierFrame(t Tunnel, networkID string, frame []byte) error {
	gt, ok := t.(*gtunnel)
	if !ok {
		return errors.New("tunnel does not support ZeroTier")
	}
	return gt.injectZeroTierFrame(networkID, frame)
}

func ClearZeroTier(t Tunnel, networkID string) error {
	gt, ok := t.(*gtunnel)
	if !ok {
		return errors.New("tunnel does not support ZeroTier")
	}
	return gt.clearZeroTier(networkID)
}

func HasZeroTierRoute(t Tunnel, addr netip.Addr) bool {
	_, ok := t.(*gtunnel)
	if !ok || !addr.IsValid() {
		return false
	}
	_, ok = ZeroTierNICForAddress(t, addr)
	return ok
}

func ZeroTierNICForAddress(t Tunnel, addr netip.Addr) (tcpip.NICID, bool) {
	gt, ok := t.(*gtunnel)
	if !ok || !addr.IsValid() {
		return 0, false
	}
	gt.ztMu.Lock()
	defer gt.ztMu.Unlock()
	bestBits, bestMetric, bestID := -1, uint32(^uint32(0)), ""
	var bestNIC tcpip.NICID
	check := func(prefix netip.Prefix, metric uint32, id string, nic tcpip.NICID) {
		if !prefix.Contains(addr) {
			return
		}
		if prefix.Bits() > bestBits || prefix.Bits() == bestBits && (metric < bestMetric || metric == bestMetric && (bestID == "" || id < bestID)) {
			bestBits, bestMetric, bestID, bestNIC = prefix.Bits(), metric, id, nic
		}
	}
	for id, network := range gt.ztNets {
		for _, route := range network.routes {
			check(route.prefix, route.metric, id, network.nicID)
		}
		for _, address := range network.addresses {
			check(address, 0, id, network.nicID)
		}
	}
	return bestNIC, bestBits >= 0
}

// DialZeroTier opens a TCP or UDP flow directly on the secondary NIC. Intra
// calls this only after its normal firewall and proxy-selection checks pass.
func DialZeroTier(t Tunnel, network, remote string) (net.Conn, error) {
	gt, ok := t.(*gtunnel)
	if !ok {
		return nil, errors.New("tunnel does not support ZeroTier")
	}
	addr, proto := fulladdr(remote)
	if addr == nil {
		return nil, fmt.Errorf("invalid ZeroTier destination %q", remote)
	}
	ipp, err := netip.ParseAddrPort(remote)
	if err != nil {
		return nil, err
	}
	addr.NIC, ok = ZeroTierNICForAddress(t, ipp.Addr())
	if !ok {
		return nil, fmt.Errorf("no ZeroTier route to %s", ipp.Addr())
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialTCP(gt.stack, *addr, proto)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(gt.stack, nil, addr, proto)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func parsePrefixes(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", item, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

type routeSpec struct {
	prefix  netip.Prefix
	gateway netip.Addr
	metric  uint32
}

func parseRoutes(csv string) ([]routeSpec, error) {
	var out []routeSpec
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		metric := uint32(0)
		if i := strings.LastIndexByte(item, '@'); i >= 0 {
			v, err := strconv.ParseUint(strings.TrimSpace(item[i+1:]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid route metric %q", item[i+1:])
			}
			metric, item = uint32(v), item[:i]
		}
		parts := strings.Split(item, "=")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid route %q", item)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid route prefix %q: %w", parts[0], err)
		}
		r := routeSpec{prefix: p.Masked(), metric: metric}
		if len(parts) == 2 {
			r.gateway, err = netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err != nil || r.gateway.Is4() != p.Addr().Is4() {
				return nil, fmt.Errorf("invalid route gateway %q", parts[1])
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func routesForNIC(prefixes []routeSpec, nic tcpip.NICID) ([]tcpip.Route, error) {
	out := make([]tcpip.Route, 0, len(prefixes))
	for _, route := range prefixes {
		p := route.prefix
		addr := tcpip.Address{}
		bits := 0
		if p.Addr().Is4() {
			addr = tcpip.AddrFrom4(p.Addr().As4())
			bits = 32
		} else {
			addr = tcpip.AddrFrom16(p.Addr().As16())
			bits = 128
		}
		mask := tcpip.MaskFromBytes(net.CIDRMask(p.Bits(), bits))
		dst, err := tcpip.NewSubnet(addr, mask)
		if err != nil {
			return nil, fmt.Errorf("invalid route %s: %w", p, err)
		}
		var gateway tcpip.Address
		if route.gateway.IsValid() {
			gateway = tcpip.AddrFromSlice(route.gateway.AsSlice())
		}
		out = append(out, tcpip.Route{Destination: dst, Gateway: gateway, NIC: nic})
	}
	return out, nil
}

func replaceZeroTierAddresses(s *stack.Stack, nicID tcpip.NICID, prefixes []netip.Prefix) error {
	for id, info := range s.NICInfo() {
		if id != nicID {
			continue
		}
		for _, addr := range info.ProtocolAddresses {
			if err := s.RemoveAddress(nicID, addr.AddressWithPrefix.Address); err != nil {
				return errors.New(err.String())
			}
		}
	}
	for _, p := range prefixes {
		var proto tcpip.NetworkProtocolNumber
		var addr tcpip.Address
		if p.Addr().Is4() {
			proto = ipv4.ProtocolNumber
			addr = tcpip.AddrFrom4(p.Addr().As4())
		} else {
			proto = ipv6.ProtocolNumber
			addr = tcpip.AddrFrom16(p.Addr().As16())
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: p.Bits()}}
		if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint}); err != nil {
			return errors.New(err.String())
		}
	}
	return nil
}

func (t *gtunnel) Stat() (*x.NetStat, error) {
	st, err := netstack.Stat(t.stack)
	if err == nil && st != nil {
		st.TUNSt.Open = !t.closed.Load()
		st.TUNSt.Up = t.ep.IsAttached()
		st.TUNSt.Sid = t.sid.Load() // session id (tunnel fd)
		st.TUNSt.Mtu = int32(t.ep.MTU())
		st.TUNSt.PcapMode = t.pcapio.mode()
		st.TUNSt.EpStats = t.ep.Stat().String()

		if t := t.hdl.TCP(); t != nil {
			st.RDNSIn.OpenConnsTCP = t.OpenConns()
		}
		if u := t.hdl.UDP(); u != nil {
			st.RDNSIn.OpenConnsUDP = u.OpenConns()
		}
		if i := t.hdl.ICMP(); i != nil {
			st.RDNSIn.OpenConnsICMP = i.OpenConns()
		}
	}
	return st, err
}

// copy so golang gc may not close orig fd
func maybeDup(fd int) (int, error) {
	if fd < 0 {
		return 0, errInvalidTunFd
	}
	if settings.OwnTunFd.Load() {
		// if OwnTunFd is true, then do not dup the fd
		// as netstack owns the TUN fd and will not
		// assume ownership of the TUN fd shared with it.
		log.I("tun: assuming fd ownership %d", fd)
		return fd, nil
	}

	// ref: github.com/mdlayher/socket/blob/9c51a391b/conn.go#L309
	// fctnl(2) to dup the fd & set cloexec in one syscall
	newfd, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil { // success
		return newfd, nil
	} else if err == unix.EINVAL { // fallback
		// Mirror the standard library: avoid racing a fork/exec with dup
		// so that child does not inherit socket fds unexpectedly.
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()

		newfd, err := unix.Dup(fd)
		if err == nil {
			unix.CloseOnExec(newfd)
		}
		return newfd, err
	} // other errors?
	return 0, os.NewSyscallError("fcntl", err)
}
