package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	if handle, err := pcap.OpenLive("bond1",1600,true,pcap.BlockForever); err == nil {
		err = handle.SetBPFFilter("port 3301")
		if err != nil {
			fmt.Println(err)
			return
		}
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for v := range source.Packets() {
			if payload := v.Layer(gopacket.LayerTypePayload); payload != nil {
				fmt.Println(string(payload.LayerContents()))
			}
		}
	}
}