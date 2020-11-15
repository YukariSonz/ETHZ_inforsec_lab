package main

import (
    "fmt"
    "plugin"

    "student.ch/netsec/isl/defense/common"
)

var printPktIP    func(common.PktIP)
var printPktUDP   func(common.PktUDP)
var printPktSCION func(common.PktSCION)

func runFirewall(libPath string, done chan int) {
    plug, err := plugin.Open(libPath)
    if err != nil {
        fmt.Println(err)
        done <- 1
    }

    // Define callback function
    SetCallback, err := plug.Lookup("SetCallback")
    if err != nil {
        fmt.Println(err)
        done <- 1
    }
    f := SetCallback.(func(common.Callback))
    f(ForwardPacket)

    // Get function to print IP packets
    PrintPktIP, err := plug.Lookup("PrintPktIP")
    if err != nil {
        fmt.Println(err)
        done <- 1
    }
    printPktIP = PrintPktIP.(func(common.PktIP))

    // Get function to print UDP packets
    PrintPktUDP, err := plug.Lookup("PrintPktUDP")
    if err != nil {
        fmt.Println(err)
        done <- 1
    }
    printPktUDP = PrintPktUDP.(func(common.PktUDP))

    // Get function to print SCION packets
    PrintPktSCION, err := plug.Lookup("PrintPktSCION")
    if err != nil {
        fmt.Println(err)
        done <- 1
    }
    printPktSCION = PrintPktSCION.(func(common.PktSCION))

    // Start firewall
    Run, err := plug.Lookup("Run")
    if err != nil {
        fmt.Println(err)
        done <- 1
    }

    r, ok := Run.(func())
    if !ok {
        fmt.Println("unexpected type from module symbol")
        done <- 1
    }
    r()
    done <- 0
}
