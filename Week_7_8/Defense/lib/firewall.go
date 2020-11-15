package main

import (
    "encoding/binary"
    "bytes"
    "encoding/hex"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/chifflier/nfqueue-go/nfqueue"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "student.ch/netsec/isl/defense/common"
)

var (
    webserverIP         = []byte{172, 22, 0, 2}
    forwardStudent      common.Callback
)

const (
    sizeHeaderIP        = 20
    sizeHeaderUDP       = 8
    sizeHeaderScnMin    = 32
    maxTTL              = 24 * 60 * 60
    expTimeUnit         = maxTTL / 256
)

func PrintPktIP(p common.PktIP) {
    fmt.Println("/--------------------")
    fmt.Println("| IP")
    fmt.Println("| - SrcIP:", net.IP(p.SrcIP))
    fmt.Println("| - DstIP:", net.IP(p.DstIP))
    fmt.Println("/--------------------")
    fmt.Println("")
}

func PrintPktUDP(p common.PktUDP) {
    fmt.Println("/-----------------")
    fmt.Println("| UDP")
    fmt.Println("| - SrcPort:", p.SrcPort)
    fmt.Println("| - DstPort:", p.DstPort)
    fmt.Println("/-----------------")
    fmt.Println("")
}

func PrintPktSCION(p common.PktSCION) {
    fmt.Println("/---------------------------------")
    fmt.Println("| SCION")
    fmt.Println("| = Common Header")
    fmt.Println("|   - Ver:", p.Ver)
    fmt.Println("|   - SrcType:", p.SrcType)
    fmt.Println("|   - TotalLen:", p.TotalLen)
    fmt.Println("|   - HdrLen:", p.HdrLen)
    fmt.Println("|   - CurrInfoF:", p.CurrInfoF)
    fmt.Println("|   - CurrHopF:", p.CurrHopF)
    fmt.Println("|   - NextHdr:", p.NextHdr)
    fmt.Println("| = Address Header")
    fmt.Println("|   - SrcISD:", p.SrcISD)
    fmt.Println("|   - SrcAS:", p.SrcAS)
    fmt.Println("|   - DstISD:", p.DstISD)
    fmt.Println("|   - DstAS:", p.DstAS)
    fmt.Println("|   - DstHost:", net.IP(p.DstHost))
    fmt.Println("|   - SrcHost:", net.IP(p.SrcHost))
    fmt.Println("| = SCION Path Type Header")

    for i, inf := range p.Segments {
        fmt.Println("|   = InfoField", i)
        fmt.Println("|     - ConsDir:", inf.ConsDir)
        fmt.Println("|     - Shortcut:", inf.Shortcut)
        fmt.Println("|     - Peer:", inf.Peer)
        fmt.Println("|     - TsInt:", toTimestamp(inf.TsInt))
        fmt.Println("|     - ISD:", inf.ISD)
        fmt.Println("|     - Hops:", inf.Hops)

        for j, seg := range inf.HopFields {
            fmt.Println("|     = HopField", j)
            fmt.Println("|       - Xover:", seg.Xover)
            fmt.Println("|       - VerifyOnly:", seg.VerifyOnly)
            fmt.Println("|       - ExpTime:", toDuration(seg.ExpTime))
            fmt.Println("|       - ConsIngress:", seg.ConsIngress)
            fmt.Println("|       - ConsEgress:", seg.ConsEgress)
            fmt.Println("|       - Mac:", "0x"+hex.EncodeToString(seg.Mac))
        }
    }

    fmt.Println("/---------------------------------")
    fmt.Println("")
}

func parse_HopField(b []byte) (*common.HopField) {
    h := &common.HopField{}
    flags := b[0]
    h.Xover = flags&0x01 != 0
    h.VerifyOnly = flags&0x02 != 0
    h.ExpTime = uint8(b[1])
    ifids := binary.BigEndian.Uint32(b[1:5])
    h.ConsIngress = uint16((ifids >> 12) & 0xFFF)
    h.ConsEgress = uint16(ifids & 0xFFF)
    h.Mac = make([]byte, 3)
    copy(h.Mac, b[5:8])
    return h
}

func parse_InfoField(b []byte) (*common.InfoField) {
    inf := &common.InfoField{}
    flags := b[0]
    inf.ConsDir = flags&0x1 != 0
    inf.Shortcut = flags&0x2 != 0
    inf.Peer = flags&0x4 != 0
    offset := 1
    inf.TsInt = binary.BigEndian.Uint32(b[offset:])
    offset += 4
    inf.ISD = binary.BigEndian.Uint16(b[offset:])
    offset += 2
    inf.Hops = b[offset]
    return inf
}

func toDuration(e uint8) time.Duration {
    return (time.Duration(e) + 1) * time.Duration(expTimeUnit) * time.Second
}

func toTimestamp(t uint32) time.Time {
    return time.Unix(int64(t), 0)
}

// Receive a packet and decide whether to accept (return true) or drop (return false)
func forward(packet* common.Pkt) bool {
    return true;
}

// Parse IP header
func parse_IP(input []byte) (parsedPacketIP *common.PktIP, payloadIP []byte, err error) {
    layer_ip := layers.IPv4{}
    if err := layer_ip.DecodeFromBytes(input, gopacket.NilDecodeFeedback); err != nil {
        return nil, nil, errors.New("[IP] Parsing failed.")
    }
    packetIP := &common.PktIP{}
    packetIP.SrcIP, packetIP.DstIP = layer_ip.SrcIP, layer_ip.DstIP
    //fmt.Println("[IP] Src:", packetIP.SrcIP, "\tDst:", packetIP.DstIP)
    return packetIP, layer_ip.Payload, nil
}

// Parse UDP header
func parse_UDP(input []byte) (parsedPacketUDP *common.PktUDP, payloadUDP []byte, err error) {
    layer_udp := layers.UDP{}
    if err := layer_udp.DecodeFromBytes(input, gopacket.NilDecodeFeedback); err != nil {
        return nil, nil, errors.New("[UDP] Parsing failed.")
    }
    packetUDP := &common.PktUDP{}
    packetUDP.SrcPort, packetUDP.DstPort = uint16(layer_udp.SrcPort), uint16(layer_udp.DstPort)
    //fmt.Printf("[UDP] Src.Port: %d\tDst.Port: %d\n", packetUDP.SrcPort, packetUDP.DstPort)
    return packetUDP, layer_udp.Payload, nil
}

// Parse SCION header
func parse_SCION(input []byte) (parsedPacketSCION *common.PktSCION, payloadSCION []byte, err error) {
    // Parse common header
    if len(input) < sizeHeaderScnMin {
        return nil, nil, errors.New("[SCION] Packet is shorter than the minimal SCION header (common header and address header).")
    }
    p := &common.PktSCION{}
    var offset uint16 = 0
    verDstSrc := binary.BigEndian.Uint16(input[offset:])
    p.Ver = uint8(verDstSrc >> 12)
    p.DstType = uint8(verDstSrc>>6) & 0x3F
    p.SrcType = uint8(verDstSrc) & 0x3F
    offset += 2
    p.TotalLen = binary.BigEndian.Uint16(input[offset:])
    offset += 2
    p.HdrLen = uint16(input[offset])*8
    offset += 1
    p.CurrInfoF = uint16(input[offset])*8
    offset += 1
    p.CurrHopF = uint16(input[offset])*8
    offset += 1
    p.NextHdr = uint8(input[offset])
    if p.Ver != 0 {
        fmt.Printf("[SCION] wrong version\n")
    }

    // Parse address header
    offset = 8
    p.DstISD = binary.BigEndian.Uint16(input[offset:])
    offset += 2
    p.DstAS = make([]byte, 6)
    copy(p.DstAS, input[offset:])
    offset += 6
    p.SrcISD = binary.BigEndian.Uint16(input[offset:])
    offset += 2
    p.SrcAS = make([]byte, 6)
    copy(p.SrcAS, input[offset:])
    offset += 6
    p.DstHost = make([]byte, 4)
    copy(p.DstHost, input[offset:])
    offset += 4
    p.SrcHost = make([]byte, 4)
    copy(p.SrcHost, input[offset:])
    offset += 4

    // Parse SCION path type header
    var remainingBytes uint16 = p.HdrLen - offset
    if remainingBytes == 0 {
        return p, input[p.HdrLen:], nil
    }

    if remainingBytes % 8 != 0 {
        return nil, nil, errors.New("[SCION] Info Fields and Hop Fields have invalid size.")
    }

    // Parse Info Fields
    for h := 0; h < 3; h++ {
        info := parse_InfoField(input[offset:])
        var hopfields1 []common.HopField
        offset += 8
        remainingBytes = p.HdrLen - offset

        if remainingBytes < uint16(info.Hops*8) {
            return nil, nil, errors.New("[SCION] Not as many Hop Fields as specified in the Info Field.")
        }

        // Parse Hop Fields
        for i := uint8(0); i < info.Hops; i++ {
            hf := parse_HopField(input[offset:])
            offset += 8
            remainingBytes = p.HdrLen - offset
            hopfields1 = append(hopfields1, *hf)
        }
        info.HopFields = hopfields1
        p.Segments = append(p.Segments, *info)

        if remainingBytes == 0 {
            break
        }
    }

    return p, input[p.HdrLen:], nil
}

func isWebserverIP(IP []byte) bool {
    if len(IP) != 4 {
        return false
    }
    return bytes.Equal(IP, webserverIP)
}

func parse(payload *nfqueue.Payload) int {
    // Assumes the following stack:
    // | UDP   |
    // | SCION |
    // | UDP   |
    // | IP    |

    // Parse IP header
    raw_data := payload.Data
    //fmt.Println("Total length: ", len(raw_data))
    _, payloadIP, err := parse_IP(raw_data)
    if err != nil {
        fmt.Println(err)
    }

    // Parse lower UDP header
    _, payloadUDP, err := parse_UDP(payloadIP)
    if err != nil {
        fmt.Println(err)
    }

    // Parse SCION common header
    packetSCION, payloadSCION, err := parse_SCION(payloadUDP)
    if err != nil {
        fmt.Println(err)
    }

    // Forward/accept packets that are not sent to the https server
    if !isWebserverIP(packetSCION.DstHost) {
        payload.SetVerdict(nfqueue.NF_ACCEPT)
        return 0
    }

    packetUDP, payloadUpper, err := parse_UDP(payloadSCION)
    if err != nil {
        fmt.Println(err)
    }

    // Create packet with all the parsed fields
    packet := &common.Pkt{
        SCION:   *packetSCION,
        UDP:     *packetUDP,
        Payload: payloadUpper,
    }

    // Accept (NF_ACCEPT) or drop (NF_DROP) the packet
    if forwardStudent(packet) {
        payload.SetVerdict(nfqueue.NF_ACCEPT)
    } else {
        payload.SetVerdict(nfqueue.NF_DROP)
    }

    return 0
}

func SetCallback(c common.Callback) {
    forwardStudent = c
}

func Run() {
    fmt.Println("[ISL] Starting firewall")

    log.SetOutput(ioutil.Discard)
    q := new(nfqueue.Queue)
    q.SetCallback(parse)
    q.Init()
    q.Unbind(syscall.AF_INET)
    q.Bind(syscall.AF_INET)
    q.CreateQueue(0)

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func(){
        for sig := range c {
            // sig is a ^C, handle it
            _ = sig
            q.StopLoop()
        }
    }()

    q.Loop()
    q.DestroyQueue()
    q.Close()
    fmt.Println("[ISL] Stopping firewall")
}

func main() {
    forwardStudent = forward
    Run()
}
