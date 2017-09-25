// dbsniffer.go
// trying to sniff MySQL、Redis、Mongodb query streams and statics information realtime;

package main

import (
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

const (
	COM_SLEEP = 0
	COM_QUIT = 1
	COM_INIT_DB = 2
	COM_QUERY = 3
	COM_FIELD_LIST = 4
	COM_CREATE_DB = 5
	COM_DROP_DB = 6
	COM_REFRESH = 7
	COM_SHUTDOWN = 8
	COM_STATISTICS = 9
	COM_PROCESS_INFO = 10
	COM_CONNECT = 11
	COM_PROCESS_KILL = 12
	COM_DEBUG = 13
	COM_PING = 14
	COM_TIME = 15
	COM_DELAYED_INSERT = 16
	COM_CHANGE_USER = 17
	COM_BINLOG_DUMP = 18
	COM_TABLE_DUMP = 19
	COM_CONNECT_OUT = 20
	COM_REGISTER_SLAVE = 21
	COM_STMT_PREPARE = 22
	COM_STMT_EXECUTE = 23
	COM_STMT_SEND_LONG_DATA = 24
	COM_STMT_CLOSE = 25
	COM_STMT_RESET = 26
	COM_SET_OPTION = 27
	COM_STMT_FETCH = 28
	COM_DAEMON = 29
	COM_END = 30


)

var (
	snapshotLen int32 = 1024
	promiscuous bool = false
	err error
	timeout time.Duration = 30*time.Second
	handle *pcap.Handle
	tcpLayer layers.TCP
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
	reqSent *time.Time
	qtext string
	qdata []byte
	responseTime *time.Time
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
	channels := [8]chan gopacket.Packet
	for i:=0;i <8; i++{
		channels[i] =make(chan gopacket.Packet)
		go handlePacket(channels[i],port)
	}
	for packet := range packetSource.Packets(){
		if tcp := packet.TransportLayer(); tcp !=nil{
			channels[int(tcp.TransportFlow().FastHash()) & 0x7] <-packet
		}
		//handlePacket(packet,port)
	}
}

func handlePacket(packet gopacket.Packet,port *int){
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip,_ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp,_ := tcpLayer.(*layers.TCP)
			srcIp := ip.SrcIP.String()
			// dstIp := ip.DstIP.String()
			requestTime := time.Now()
			if tcp.DstPort.String() == fmt.Sprintf("%d",*port) {
				rs := &source{
					srcPort: 	fmt.Sprintf("%d",tcp.SrcPort),
					srcIp:		srcIp,
					reqSent: 	&requestTime,
					qdata:		tcp.Payload,
				}
				seqNumber := tcp.Seq + uint32(len(tcp.Payload))
				log.Printf("request from %s:%s and time is %s and seqNumber is %d",srcIp,rs.srcPort,*rs.reqSent,seqNumber)
				_, queryData:= parsePacket(&(rs.qdata))
				rs.qtext = string(queryData) 
				//log.Printf("query context is %s and queryType is %d",tcp.Payload,queryType)
			} else if tcp.SrcPort.String() == fmt.Sprintf("%d", *port) {
				// lantecy := time.Since(*rs.reqSent).Nanoseconds
				seqNumber := tcp.Seq + uint32(len(tcp.Payload))
				log.Printf("response from %s:%s and time is %s and seqNumber is %d",srcIp,tcp.SrcPort.String(),time.Now(),seqNumber)
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