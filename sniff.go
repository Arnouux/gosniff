package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
)

func main() {
	fmt.Println("hi")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("error")
	}

	for _, device := range devices {
		fmt.Printf("Device Name: %s\n", device.Name)
		fmt.Printf("Device Description: %s\n", device.Description)
		fmt.Printf("Device Flags: %d\n", device.Flags)
		for _, iaddress := range device.Addresses {
			fmt.Printf("\tInterface IP: %s\n", iaddress.IP)
			fmt.Printf("\tInterface NetMask: %s\n", iaddress.Netmask)
		}
	}
	
	infs, _ := net.Interfaces()
	for _, f := range infs {
		fmt.Println(f.Name)
	}
}