package rtcp

import (
	"log"
)

// Packet represents an RTCP packet, a protocol used for out-of-band statistics and control information for an RTP session
type Packet interface {
	// DestinationSSRC returns an array of SSRC values that this packet refers to.
	DestinationSSRC() []uint32

	Marshal() ([]byte, error)
	Unmarshal(rawPacket []byte) error
}

// Unmarshal takes an entire udp datagram (which may consist of multiple RTCP packets) and
// returns the unmarshaled packets it contains.
//
// If this is a reduced-size RTCP packet a feedback packet (Goodbye, SliceLossIndication, etc)
// will be returned. Otherwise, the underlying type of the returned packet will be
// CompoundPacket.
func Unmarshal(rawData []byte) ([]Packet, uint64, uint32, error) {
	var packets []Packet
	for len(rawData) != 0 {
		p, processed, ntpTimestamp, packetCount, isSenderReport, err := unmarshal(rawData)

		if isSenderReport && ntpTimestamp != 0 && packetCount != 0 {
			return nil, ntpTimestamp, packetCount, nil
		}
		if err != nil {
			return nil, 0, 0, err
		}

		packets = append(packets, p)
		rawData = rawData[processed:]
	}

	switch len(packets) {
	// Empty packet
	case 0:
		return nil, 0, 0, errInvalidHeader
	// Multiple Packets
	default:
		return packets, 0, 0, nil
	}
}

// Marshal takes an array of Packets and serializes them to a single buffer
func Marshal(packets []Packet) ([]byte, error) {
	out := make([]byte, 0)
	for _, p := range packets {
		data, err := p.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
	}
	return out, nil
}

// unmarshal is a factory which pulls the first RTCP packet from a bytestream,
// and returns it's parsed representation, and the amount of data that was processed.
func unmarshal(rawData []byte) (packet Packet, bytesprocessed int, ntpTimestamp uint64, packetCount uint32, isSenderReport bool, err error) {
	var h Header

	err = h.Unmarshal(rawData)
	if err != nil {
		return nil, 0, 0, 0, false, err
	}

	bytesprocessed = int(h.Length+1) * 4
	if bytesprocessed > len(rawData) {
		return nil, 0, 0, 0, false, errPacketTooShort
	}
	inPacket := rawData[:bytesprocessed]

	switch h.Type {
	case TypeSenderReport:
		packet = new(SenderReport)
	case TypeReceiverReport:
		packet = new(ReceiverReport)

	case TypeSourceDescription:
		packet = new(SourceDescription)

	case TypeGoodbye:
		packet = new(Goodbye)

	case TypeTransportSpecificFeedback:
		switch h.Count {
		case FormatTLN:
			packet = new(TransportLayerNack)
		case FormatRRR:
			packet = new(RapidResynchronizationRequest)
		case FormatTCC:
			packet = new(TransportLayerCC)
		default:
			packet = new(RawPacket)
		}

	case TypePayloadSpecificFeedback:
		switch h.Count {
		case FormatPLI:
			packet = new(PictureLossIndication)
		case FormatSLI:
			packet = new(SliceLossIndication)
		case FormatREMB:
			packet = new(ReceiverEstimatedMaximumBitrate)
		case FormatFIR:
			packet = new(FullIntraRequest)
		default:
			packet = new(RawPacket)
		}

	case TypeExtendedReport:
		packet = new(ExtendedReport)

	default:
		packet = new(RawPacket)
	}

	isSender := false

	if h.Type == TypeSenderReport {
		senderReport := new(SenderReport)
		err_senderReport := senderReport.Unmarshal(inPacket)

		if err_senderReport != nil {
			log.Println(err_senderReport)
		}

		ntpTimestamp = senderReport.NTPTime
		packetCount = senderReport.PacketCount
		isSender = true
		err = packet.Unmarshal(inPacket)

	} else {
		err = packet.Unmarshal(inPacket)
		ntpTimestamp = 0
		packetCount = 0
	}

	return packet, bytesprocessed, ntpTimestamp, packetCount, isSender, err
}
