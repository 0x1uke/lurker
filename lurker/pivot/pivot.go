package pivot

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	EventClose   = 4 // CALLBACK_CLOSE
	EventRead    = 5 // CALLBACK_READ
	EventConnect = 6 // CALLBACK_CONNECT
)

type Event struct {
	Type     int
	SocketID uint32
	Data     []byte
}

type conn struct {
	id       uint32
	conn     net.Conn
	listener net.Listener
	udpConn  net.PacketConn
}

var (
	mu     sync.Mutex
	conns  = make(map[uint32]*conn)
	events = make(chan Event, 256)
)

func Connect(socketID uint32, host string, port uint16) {
	go func() {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		c, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			events <- Event{Type: EventClose, SocketID: socketID}
			return
		}
		entry := &conn{id: socketID, conn: c}
		mu.Lock()
		conns[socketID] = entry
		mu.Unlock()
		events <- Event{Type: EventConnect, SocketID: socketID}
		readLoop(entry)
	}()
}

func Listen(socketID uint32, port uint16) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	entry := &conn{id: socketID, listener: ln}
	mu.Lock()
	conns[socketID] = entry
	mu.Unlock()
	go func() {
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(180 * time.Second))
		c, err := ln.Accept()
		ln.Close()
		mu.Lock()
		_, stillActive := conns[socketID]
		if !stillActive {
			mu.Unlock()
			if c != nil {
				c.Close()
			}
			return
		}
		if err != nil {
			delete(conns, socketID)
			mu.Unlock()
			events <- Event{Type: EventClose, SocketID: socketID}
			return
		}
		entry.listener = nil
		entry.conn = c
		mu.Unlock()
		events <- Event{Type: EventConnect, SocketID: socketID}
		readLoop(entry)
	}()
	return nil
}

func Send(socketID uint32, data []byte) {
	mu.Lock()
	entry, ok := conns[socketID]
	if !ok || entry.conn == nil {
		mu.Unlock()
		return
	}
	c := entry.conn
	mu.Unlock()
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(data); err != nil {
		c.Close()
	}
	c.SetWriteDeadline(time.Time{})
}

func UDPAssociate(socketID uint32) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		events <- Event{Type: EventClose, SocketID: socketID}
		return
	}
	entry := &conn{id: socketID, udpConn: pc}
	mu.Lock()
	conns[socketID] = entry
	mu.Unlock()
	events <- Event{Type: EventConnect, SocketID: socketID}
	go udpReadLoop(entry)
}

func UDPSend(socketID uint32, host string, port uint16, data []byte) {
	mu.Lock()
	entry, ok := conns[socketID]
	if !ok || entry.udpConn == nil {
		mu.Unlock()
		return
	}
	pc := entry.udpConn
	mu.Unlock()

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return
	}
	pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	pc.WriteTo(data, addr)
	pc.SetWriteDeadline(time.Time{})
}

func Close(socketID uint32) {
	mu.Lock()
	entry, ok := conns[socketID]
	if ok {
		delete(conns, socketID)
	}
	mu.Unlock()
	if ok {
		if entry.listener != nil {
			entry.listener.Close()
		}
		if entry.conn != nil {
			entry.conn.Close()
		}
		if entry.udpConn != nil {
			entry.udpConn.Close()
		}
	}
}

func Poll() []Event {
	var result []Event
	for {
		select {
		case ev := <-events:
			result = append(result, ev)
		default:
			return result
		}
	}
}

func readLoop(entry *conn) {
	buf := make([]byte, 512*1024)
	for {
		n, err := entry.conn.Read(buf)
		if n > 0 {
			data := make([]byte, 4+n)
			binary.BigEndian.PutUint32(data[:4], entry.id)
			copy(data[4:], buf[:n])
			events <- Event{Type: EventRead, SocketID: entry.id, Data: data}
		}
		if err != nil {
			mu.Lock()
			_, stillActive := conns[entry.id]
			if stillActive {
				delete(conns, entry.id)
			}
			mu.Unlock()
			if stillActive {
				entry.conn.Close()
			}
			return
		}
	}
}

func udpReadLoop(entry *conn) {
	buf := make([]byte, 65535)
	for {
		entry.udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, _, err := entry.udpConn.ReadFrom(buf)
		if n > 0 {
			data := make([]byte, 4+n)
			binary.BigEndian.PutUint32(data[:4], entry.id)
			copy(data[4:], buf[:n])
			events <- Event{Type: EventRead, SocketID: entry.id, Data: data}
		}
		if err != nil {
			mu.Lock()
			_, stillActive := conns[entry.id]
			if stillActive {
				delete(conns, entry.id)
			}
			mu.Unlock()
			if stillActive {
				entry.udpConn.Close()
			}
			return
		}
	}
}
