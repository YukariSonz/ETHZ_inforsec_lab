package main

import (
    "os"
    "student.ch/netsec/isl/defense/common"
    //"encoding/hex"
    //"fmt"
    //"sort"
    "time"
)



const (
    // Global constants
    limit = 20
    ASLimit = 50
)

var (
    // Here, you can define variables that keep state for your firewall
    //blacklist map[[]byte] int
   blacklist = make(map[string]int)
   ASBlackList = make(map[string]int)
)

func decay(blackl map[string]int){
    for true{
        time.Sleep(600 * time.Millisecond)
        for key, element := range blackl {
            if element >= 1{
                blackl[key] = element - 1
            }else{
                delete(blackl, key);
            }

        }
    }
}

func decayAS(blackl map[string]int){
    for true{
        time.Sleep(600 * time.Millisecond)
        for key, element := range blackl {
            if element >= 3{
                blackl[key] = element - 3
            }else{
                delete(blackl, key);
            }

        }
    }
}








// Helper function for inspecting packets. Feel free to change / remove this
func printPkt(packet *common.Pkt) {
    printPktSCION(packet.SCION)
    printPktUDP(packet.UDP)
}

// Decide whether to forward or drop a packet based on SCION / UDP header.
// This function receives all packets with the customer as destination




func ForwardPacket(packet *common.Pkt) bool {
    // Print packet contents (disable this before submitting your code)
    //printPkt(packet)

    //var tsList []uint32

    packetSCION := packet.SCION
    packetUDP := packet.UDP
    //In real ddos environment, it's a good idea to generate the port number, especially for udp
    srcPort := packetUDP.SrcPort
    srcPortString := string(srcPort)
    AS := packetSCION.SrcAS
    host := packetSCION.SrcHost
    
    ASHost := append(AS, host...)
    ASKey := string(AS)
    ASHostKey := string(ASHost) + srcPortString
    blacklist[ASHostKey] = blacklist[ASHostKey] + 1
    ASBlackList[ASKey] = ASBlackList[ASKey] + 1
    if blacklist[ASHostKey] > limit || ASBlackList[ASKey] > ASLimit{
        return false
    }

    //fmt.Println(blacklist[ASHostKey])
    //fmt.Println(ASBlackList[ASKey])

    // pathSegment := packetSCION.Segments
    // for i, inf := range pathSegment{
    //     fmt.Println("|   = InfoField", i)
    //     //fmt.Println("|     - ConsDir:", inf.ConsDir)
    //     //fmt.Println("|     - Shortcut:", inf.Shortcut)
    //     //fmt.Println("|     - Peer:", inf.Peer)
    //     //fmt.Println("|     - TsInt:", inf.TsInt)
    //     //fmt.Println("|     - ISD:", inf.ISD)
    //     //fmt.Println("|     - Hops:", inf.Hops)

    //     for j, seg := range inf.HopFields {
    //         fmt.Println("|     = HopField", j)
    //         fmt.Println("|       - Xover:", seg.Xover)
    //         // if j==1 && seg.Xover == false{
    //         //     return false
    //         // }
    //         //fmt.Println("|       - VerifyOnly:", seg.VerifyOnly)
            
    //         //fmt.Println("|       - ExpTime:", seg.ExpTime)
    //         //fmt.Println("|       - ConsIngress:", seg.ConsIngress)
    //         //fmt.Println("|       - ConsEgress:", seg.ConsEgress)
    //     //     fmt.Println("|       - Mac:", "0x"+hex.EncodeToString(seg.Mac))
    //     }
        
    //     // fmt.Println("|     - ConsDir:", inf.ConsDir)
    //     // fmt.Println("|     - Shortcut:", inf.Shortcut)
    //     // fmt.Println("|     - Peer:", inf.Peer)
    //     // fmt.Println("|     - TsInt:", inf.TsInt)
    //     // fmt.Println("|     - ISD:", inf.ISD)
    //     // fmt.Println("|     - Hops:", inf.Hops)
    // }
    // fmt.Println("/---------------------------------")
    //fmt.Println(tsList)
    // res1 := sort.SliceIsSorted(tsList, func(p, q int) bool {  
    //     return p < q })
    // if res1 == false{
    //     fmt.Println(res1)
    // }


    // Decision
    // | true  -> forward packet
    // | false -> drop packet
    return true;
}

func main() {
    go decay(blacklist)
    go decayAS(ASBlackList)
    done := make(chan int, 1)
    go runFirewall("/usr/local/lib/firewall.so", done) // start the firewall
    code := <-done // wait for an exit code on the channel
    os.Exit(code)
}

