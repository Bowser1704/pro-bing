package probing

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type packetConn interface {
	Close() error
	ICMPRequestType() icmp.Type
	ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error)
	SetFlagTTL() error
	SetReadDeadline(t time.Time) error
	WriteTo(b []byte, dst net.Addr) (int, error)
	SetTTL(ttl int)
	SetMark(m uint) error
	SetDoNotFragment() error
	SetIfIndex(ifIndex int)
}

type icmpConn struct {
	c       *icmp.PacketConn
	ttl     int
	ifIndex int
}

func (c *icmpConn) Close() error {
	return c.c.Close()
}

func (c *icmpConn) SetTTL(ttl int) {
	c.ttl = ttl
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *icmpConn) SetIfIndex(ifIndex int) {
	c.ifIndex = ifIndex
}

func (c *icmpv4Conn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if err := c.c.IPv4PacketConn().SetTTL(c.ttl); err != nil {
		return 0, err
	}
	var cm *ipv4.ControlMessage
	if 1 <= c.ifIndex {
		// c.ifIndex == 0 if not set interface
		if err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagInterface, true); err != nil {
			return 0, err
		}
		cm = &ipv4.ControlMessage{IfIndex: c.ifIndex}
	}

	return c.c.IPv4PacketConn().WriteTo(b, cm, dst)
}

type icmpv4Conn struct {
	icmpConn
}

func (c *icmpv4Conn) SetFlagTTL() error {
	err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpv4Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv4PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.TTL
	}
	return n, ttl, src, err
}

func (c icmpv4Conn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

type icmpV6Conn struct {
	icmpConn
}

func (c *icmpV6Conn) SetFlagTTL() error {
	err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpV6Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return n, ttl, src, err
}

func (c icmpV6Conn) ICMPRequestType() icmp.Type {
	return ipv6.ICMPTypeEchoRequest
}

func (c *icmpV6Conn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if err := c.c.IPv6PacketConn().SetHopLimit(c.ttl); err != nil {
		return 0, err
	}
	var cm *ipv6.ControlMessage
	if 1 <= c.ifIndex {
		// c.ifIndex == 0 if not set interface
		if err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagInterface, true); err != nil {
			return 0, err
		}
		cm = &ipv6.ControlMessage{IfIndex: c.ifIndex}
	}

	return c.c.IPv6PacketConn().WriteTo(b, cm, dst)
}

type udpConn struct {
	conn net.Conn

	ifIndex int
	ttl     int
}

// Close implements packetConn.
func (u *udpConn) Close() error {
	return u.conn.Close()
}

// ICMPRequestType implements packetConn.
func (*udpConn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

// ReadFrom implements packetConn.
func (u *udpConn) ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error) {
	n, err = u.conn.Read(b)
	ttl = u.ttl
	src = u.conn.RemoteAddr()
	return
}

// WriteTo implements packetConn.
func (u *udpConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return u.conn.Write(b)
}

// SetFlagTTL implements packetConn.
func (*udpConn) SetFlagTTL() error {
	return nil
}

// SetIfIndex implements packetConn.
func (u *udpConn) SetIfIndex(ifIndex int) {
	u.ifIndex = ifIndex
}

// SetTTL implements packetConn.
func (u *udpConn) SetTTL(ttl int) {
	u.ttl = ttl
}

// SetReadDeadline implements packetConn.
func (u *udpConn) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

// SetMark implements packetConn.
func (u *udpConn) SetMark(mark uint) error {
	fd, err := getRawFD(u.conn)
	if err != nil {
		return err
	}
	return os.NewSyscallError(
		"setsockopt",
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)),
	)
}

// SetDoNotFragment implements packetConn.
func (u *udpConn) SetDoNotFragment() error {
	fd, err := getRawFD(u.conn)
	if err != nil {
		return err
	}
	return os.NewSyscallError(
		"setsockopt",
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IP_PMTUDISC_DO),
	)
}

func getRawFD(conn net.Conn) (int, error) {
	// This type assertion assumes that the underlying implementation of net.Conn
	// uses a *net.TCPConn or *net.UDPConn. It may not work for all types of connections.
	switch conn := conn.(type) {
	case *net.TCPConn:
		// Get the file descriptor associated with the TCP connection
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return -1, err
		}
		var fd int
		err = rawConn.Control(func(fdPtr uintptr) {
			fd = int(fdPtr)
		})
		if err != nil {
			return -1, err
		}
		return fd, nil

	case *net.UDPConn:
		// Get the file descriptor associated with the UDP connection
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return -1, err
		}
		var fd int
		err = rawConn.Control(func(fdPtr uintptr) {
			fd = int(fdPtr)
		})
		if err != nil {
			return -1, err
		}
		return fd, nil

	default:
		return -1, fmt.Errorf("unsupported connection type")
	}
}

func newUDPConn(remote *net.UDPAddr, interfaceName string) (packetConn, error) {
	var dialer net.Dialer
	dialer.ControlContext = func(ctx context.Context, network, addr string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if interfaceName != "" {
				if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName); err != nil {
					fmt.Println("setsockopt SO_BINDTODEVICE failed: ", err)
				}
			}
		})
	}

	conn, err := dialer.Dial("udp", remote.String())

	return &udpConn{
		conn:    conn,
		ifIndex: 0,
		ttl:     0,
	}, err
}

var _ packetConn = (*udpConn)(nil)
