package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"sync"
	//"time"
	//"strings"
)

func listenDevice(device pcap.Interface) {
	fmt.Printf("Device Name: %s\n", device.Name)
	fmt.Printf("Device Description: %s\n", device.Description)
	fmt.Printf("Device Flags: %d\n", device.Flags)

	handle, err := pcap.OpenLive(device.Name, 1024, false, 5)
	if err != nil {
		fmt.Println("error openLive")
		return
	}
	defer handle.Close()
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() != nil { // ARP packets do not have Network layer
			netFlow := packet.NetworkLayer().NetworkFlow()
			src, dst := netFlow.Endpoints()
			fmt.Println(src.String() + " -> " + dst.String())
			if dst.String() == "239.255.255.250" {
				 fmt.Println("SSDP")
			}
			// } else if dst.String() == "127.0.0.1" {
			// 	fmt.Println("in")
			// } else {
			// 	fmt.Println(packet)
			// }
		}
	}
}

func main() {
	fmt.Println("hi")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("error")
		return
	}

	var wg sync.WaitGroup
	for _, device := range devices {
		wg.Add(1)
		go func(device pcap.Interface) {
			defer wg.Done()
			listenDevice(device)
		}(device)
	}
	wg.Wait()
}