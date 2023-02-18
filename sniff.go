package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	//"time"
	"strings"
)

func main() {
	fmt.Println("hi")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("error")
	}

	//var timeout time.Duration = time.Duration(5) * time.Second

	for _, device := range devices {
		if strings.Contains(device.Name, "Loopback") {
			fmt.Printf("Device Name: %s\n", device.Name)
			fmt.Printf("Device Description: %s\n", device.Description)
			fmt.Printf("Device Flags: %d\n", device.Flags)

			handle, err := pcap.OpenLive(device.Name, 1024, false, 5)
			defer handle.Close()
			if err != nil {
				fmt.Println("error openLive")
			}
			
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				fmt.Println(packet)
			}
		}
	}
}