package ipref

import (
	"encoding/binary"
	"fmt"
	. "github.com/ipref/ref"
	. "github.com/ipref/ref/newv1"
	"net"
	"regexp"
	"sync"
	"time"
)

const (
	MSGMAX = ((V1_HDR_LEN + V1_AREC_MAX_LEN + 2 + 255 + 16) / 16) * 16 // round up to 16 byte boundary (304)
)

var be = binary.BigEndian

type MapperClient struct {
	lock     sync.Mutex
	conn     *net.UnixConn
	msgid    uint16

	re_hexref *regexp.Regexp
	re_decref *regexp.Regexp
	re_dotref *regexp.Regexp
}

func (m *MapperClient) init() {
	m.msgid = uint16(time.Now().Unix() & 0xffff)
}

func (m *MapperClient) clear() {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.conn != nil {
		m.conn.Close()
	}
}

func (ipr *Ipref) encoded_address(dnm string, ea_ipver int, gw IP, ref Ref) (IP, error) {

	ea_iplen := IPVerToLen(ea_ipver)
	if ea_iplen == 0 {
		panic("unexpected")
	}

	m := ipr.m

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.conn == nil {
		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{ipr.mapper_socket, "unixpacket"})
		if err != nil {
			return IP{}, fmt.Errorf("cannot connect to mapper: %v", err)
		}
		m.conn = conn
	}

	var msg [MSGMAX]byte
	var err error

	// header

	if m.msgid += 1; m.msgid == 0 {
		m.msgid += 1;
	}

	msg[V1_VER] = V1_SIG
	msg[V1_CMD] = V1_REQ | V1_MC_GET_EA
	be.PutUint16(msg[V1_PKTID:V1_PKTID+2], uint16(m.msgid))
	msg[V1_RESERVED] = 0
	msg[V1_RESERVED+1] = 0

	// address record

	off := V1_HDR_LEN

	arec := AddrRec{
		EA: IPZero(ea_iplen),
		IP: IPZero(ea_iplen),
		GW: gw,
		Ref: ref,
	}

	off += AddrRecEncode(msg[off:], arec)

	// dns name

	msglen := off

	dnmlen := len(dnm)
	if 0 < dnmlen && dnmlen < 256 { // should be true since DNS names are shorter than 255 chars
		msg[off] = V1_TYPE_STRING
		msg[off+1] = byte(dnmlen)
		copy(msg[off+2:], dnm)
		msglen += (dnmlen + 5) &^ 3
	}

	// set wait time for response

	err = m.conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return IP{}, fmt.Errorf("cannot set mapper request deadline: %v", err)
	}

	// send request to mapper

	be.PutUint16(msg[V1_PKTLEN:V1_PKTLEN+2], uint16(msglen/4))

	_, err = m.conn.Write(msg[:msglen])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return IP{}, fmt.Errorf("map request send error: %v", err)
	}

	// read response

	rlen, err := m.conn.Read(msg[:])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return IP{}, fmt.Errorf("map request receive error: %v", err)
	}

	if rlen < V1_HDR_LEN {
		return IP{}, fmt.Errorf("response from mapper too short")
	}

	if msg[V1_VER] != V1_SIG {
		return IP{}, fmt.Errorf("response is not a v1 protocol")
	}

	if msg[V1_CMD] != V1_ACK|V1_MC_GET_EA {
		return IP{}, fmt.Errorf("map request declined by mapper")
	}

	if rlen != int(be.Uint16(msg[V1_PKTLEN:V1_PKTLEN+2])*4) {
		return IP{}, fmt.Errorf("incorrect packet length")
	}

	if be.Uint16(msg[V1_PKTID:V1_PKTID+2]) != m.msgid {
		return IP{}, fmt.Errorf("mapper response out of sequence")
	}

	ok, arec_len, arec := AddrRecDecode(msg[V1_HDR_LEN:])
	if !ok || rlen != V1_HDR_LEN + arec_len {
		return IP{}, fmt.Errorf("invalid address record")
	}
	if arec.EA.Ver() != ea_ipver || arec.GW != gw || arec.Ref != ref {
		return IP{}, fmt.Errorf("invalid address record data")
	}

	return arec.EA, nil
}
