// dbsniffer.go
// trying to sniff MySQL、Redis、Mongodb query streams and statics information realtime;

package main

import (
	"bytes"
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)
var (
	snapshotLen int32 = 1024
	promiscuous bool = false
	err error
	timeout time.Duration = 30*time.Second
	handle *pcap.Handle
	tcpLayer layers.TCP
	packetInfo = make(map[string]*source)
)

type packet struct {
	request bool //symbol whether request or response
	data []byte
}

type sortable struct {
	value float64
	line string
}

type sortableSlice []sortable

type source struct {
	srcPort string
	srcIp string
	reqTime *time.Time
	qtext string
	qdata []byte
	responseTime *time.Time
	srcSeq uint32
	lantecy int64
}


func main() {
	var port *int = flag.Int("P",3301,"database port trying to sniff,default 3306")
	var device *string = flag.String("i","bond1","Interface to sniff,default bond1")
	var period *int = flag.Int("t",10,"Seconds between output status,default 10 seconds")
	var dbType *string = flag.String("db","mysql","which kind database trying to sniff,support mysql,redis,mongodb,default mysql")
	flag.Parse()
	log.Printf("trying to sniff %s on port:%d,device:%s,period:%d",*dbType,*port,*device,*period)
	handle, err := pcap.OpenLive(*device,snapshotLen,promiscuous,timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(fmt.Sprintf("tcp port %d",*port))
	if err != nil {
		log.Fatalf("Failed to sniff port:%s",err.Error())
	}	
	packetSource := gopacket.NewPacketSource(handle,handle.LinkType())

	for packet := range packetSource.Packets() {
		// if tcp := packet.TransportLayer(); tcp !=nil{
		// 	channels[int(tcp.TransportFlow().FastHash()) & 0x7] <-packet
		// }
		handlePacket(packet,port)

	}
}

func handlePacket(packet gopacket.Packet,port *int) {
	
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip,_ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp,_ := tcpLayer.(*layers.TCP)
			srcIp := ip.SrcIP.String()
			// dstIp := ip.DstIP.String()
			// dstIp := ip.DstIP.String()
			if tcp.DstPort.String() == fmt.Sprintf("%d",*port) {
				nextSeqNumber := tcp.Seq + uint32(len(tcp.Payload))
				
				if len(tcp.Payload) != 0 {
					rs := &source{
						srcPort: 	fmt.Sprintf("%d",tcp.SrcPort),
						srcIp:		srcIp,
						srcSeq:		nextSeqNumber,
					}
					var Buf bytes.Buffer
					Buf.WriteString(rs.srcIp)
					Buf.WriteString(":")
					Buf.WriteString(rs.srcPort)
					Buf.WriteString(":")
					Buf.WriteString(fmt.Sprintf("%d",rs.srcSeq))
					rsKey := Buf.String()
					ts := time.Now()
					rs.reqTime = &ts
					rs.qdata = tcp.Payload
					queryType, queryData:= parsePacket(&(rs.qdata))
					rs.qtext = string(queryData)
					packetInfo[rsKey] = rs 
					// log.Printf("query context is %s and queryType is %d",tcp.Payload,queryType)
					if queryType != 1 && queryType !=133 &&queryType != 135 {
						log.Printf("%s:%s\t%s\t%d\t%s\t%d",rs.srcIp,rs.srcPort,*rs.reqTime,rs.srcSeq,rs.qtext,queryType)
						// log.Println(tcp.Payload)
						//log.Printf("%s:%s\t%s\t%s",rs.srcIp,rs.srcPort,*rs.reqTime,rs.qtext)
					}
				}else {
					var buf bytes.Buffer
					buf.WriteString(srcIp)
					buf.WriteString(":")
					buf.WriteString(fmt.Sprintf("%d",tcp.SrcPort))
					buf.WriteString(":")
					buf.WriteString(fmt.Sprintf("%d",nextSeqNumber))
					responseKey := buf.String()
					if rs,ok := packetInfo[responseKey]; ok {
						if rs.reqTime != nil {
							lantecy := time.Since(*rs.reqTime).Nanoseconds()/1000
							rs.lantecy = lantecy
							log.Printf("%s\t%s\t%dms",responseKey,rs.qtext,rs.lantecy)
							//log.Printf("%s:%s\t%s\t%s\t%d\t%dms\t%s",rs.srcIp,rs.srcPort,*rs.reqTime,rs.qtext,rs.srcSeq,lantecy,time.Now())
							// log.Printf("\t%dms",lantecy)
						}
					}
					
				}
				// log.Printf("request from %s:%s and time is %s and seqNumber is %d",srcIp,rs.srcPort,*rs.reqTime,seqNumber)
				// _, queryData:= parsePacket(&(rs.qdata))
				// rs.qtext = string(queryData) 
				// log.Printf("query context is %s and queryType is %d",tcp.Payload,queryType)
			// } else if tcp.SrcPort.String() == fmt.Sprintf("%d", *port) {
			// 	seqNumber := tcp.Seq + uint32(len(tcp.Payload))
			// 	// lantecy := time.Since(*rs.reqSent).Nanoseconds
			// 	responseMap := make(map[string] *time.Time)
			// 	rTime := time.Now()
			// 	responseMap[buf.String()] = &rTime
			// 	// if v,ok := responseMap[rsKey]; ok{
				// 	log.Printf("response from %s:%s to %s and time is %s and seqNumber is %d",rs.srcIp,tcp.SrcPort.String(),rsKey,*v,seqNumber)
				// } else {
				// 	log.Printf("can not find request ,response from %s:%s to %s and time is %s and seqNumber is %d",rs.srcIp,tcp.SrcPort.String(),buf.String(),*responseMap[buf.String()],seqNumber)
				// }
				// packetInfo[rsKey] = rs
				// for key,value := range packetInfo{
				// 	log.Printf("%s\t%s\t%dms",key,value.qtext,value.lantecy)
			}
		}
	}
}

func parsePacket(b *[]byte) (int, []byte){
	tcpLen := uint32(len(*b))
	if tcpLen <5 {
		return -1,nil
	}
	tcpSize := uint32((*b)[0]) + uint32((*b)[1])<<8 + uint32((*b)[2])<<16
	if tcpSize == 0 || tcpLen < tcpSize+4 {
		return -1,nil
	}
	tcpEnd := tcpSize + 4
	queryType := int((*b)[4])
	data := (*b)[5:tcpSize+4]
	if tcpEnd >= tcpLen {
		*b = nil
	} else {
		*b = (*b)[tcpEnd:]
	}
	//log.Printf("queryType is %d and tcpLen is %d,tcpSize is %d,tcpEnd is %d,qdata is %s",queryType,tcpLen,tcpSize,tcpEnd,data)
	return queryType, data
}