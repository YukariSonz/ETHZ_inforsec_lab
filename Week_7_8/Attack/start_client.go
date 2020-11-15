package main

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"flag"

	"student.ch/netsec/isl/attack/client"
	"student.ch/netsec/isl/attack/help"
	"student.ch/netsec/isl/attack/meow"
)

func main() {
	spoof := flag.Bool("spoof", false, "Toggles between the Client example and your implementation of the spoofing client.\nA value of false (default) will invoce the example client.")
	remote := flag.Bool("remote", false, "Spoofing Client will be passed the local reflection address if false (default). Set for grading and during remote test.")
	flag.Parse()

	ctx := context.Background()
	isd, err := help.FindLocalISD()
	if err != nil {
		log.Println(err)
		return
	}
	ia, err := help.FindLocalAs()
	if err != nil {
		log.Println(err)
		return
	}
	serverAddr := isd + "-" + ia + "," + meow.SERVER_IP + ":" + strconv.FormatUint(meow.SERVER_PORTS[0], 10)
	if !*spoof { // non spoofing mode
		err := client.Client(ctx, serverAddr, client.GenerateClientPayload())
		if err != nil {
			log.Println(err)
		}
	} else { // spoofing mode
		var spoofedAddr string
		if *remote {
			spoofedAddr = client.VICTIM_SCION_ADDR + "," + client.VICTIM_IP + ":" + strconv.Itoa(help.LoadVictimPort())
		} else {
			spoofedAddr = isd + "-" + ia + "," + client.LOCAL_REFLECTION_IP + ":" + strconv.Itoa(help.LoadVictimPort())
		}
		err := client.Attack(ctx, serverAddr, spoofedAddr, client.GenerateAttackPayload())
		if err != nil {
			fmt.Println(err)
		}
	}
	return
}
