package common

type PktIP struct {
    SrcIP []byte
    DstIP []byte
}

type PktUDP struct {
    SrcPort uint16
    DstPort uint16
}

type PktSCION struct {
    // Common header
    Ver       uint8
    DstType   uint8
    SrcType   uint8
    TotalLen  uint16
    HdrLen    uint16
    CurrInfoF uint16
    CurrHopF  uint16
    NextHdr   uint8

    // Address header
    SrcISD    uint16
    SrcAS     []byte
    DstISD    uint16
    DstAS     []byte
    DstHost   []byte
    SrcHost   []byte

    // SCION Path Type header
    Segments []InfoField

    // Left out:
    // Hop-by-hop extensions
    // End-to-end extensions
    // L4 headers
    // Payload
}

type Pkt struct {
    SCION   PktSCION
    UDP     PktUDP
    Payload []byte
}

type InfoField struct {
    // Previously Up, ConsDir = !Up
    ConsDir  bool
    Shortcut bool
    Peer     bool
    // TsInt is the timestamp that denotes when the propagation of a path segment started.
    // Use Timestamp() to get a time.Time value.
    TsInt    uint32
    // ISD denotes the origin ISD of a path segment.
    ISD      uint16
    Hops     uint8

    HopFields []HopField
}

type HopField struct {
    Xover       bool
    VerifyOnly  bool
    // ExpTime defines for how long this HopField is valid, expressed as the number
    // of ExpTimeUnits relative to the PathSegments's InfoField.Timestamp().
    // A 0 value means the minimum expiration time of ExpTimeUnit.
    // See ToDuration() for how to convert from ExpTimeUnits to Seconds.
    ExpTime     uint8
    // ConsIngress is the interface the PCB entered the AS during path construction.
    ConsIngress uint16
    // ConsEgress is the interface the PCB exited the AS during path construction.
    ConsEgress  uint16
    // Mac is the message authentication code of this HF,
    // see CalcMac() to see how it should be calculated.
    Mac         []byte
}
