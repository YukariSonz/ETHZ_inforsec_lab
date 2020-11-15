package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"student.ch/netsec/isl/attack/meow"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
)

// Example on how to generate a payload with the public meow API
func GenerateClientPayload() []byte {
	// Choose which request to send
	var q meow.Query = "4"
	// Use API to build request
	request := meow.NewRequest(q, meow.AddFlag("debug"))

	// serialize the request with json.Marshal
	d, err := json.Marshal(request)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	}
	return d
}

// Client is a simple udp-client example which speaks udp over scion through the appnet API.
// The payload is sent to the given address exactly once and the answer is printed to
// standard output.
// serverAddr: The server IP addr and port in the form: ISD-IA,IP:port
func Client(ctx context.Context, serverAddr string, payload []byte) (err error) {

	/* Appnet is a high level API provided by the scionlab team which facilitates sending and
	receiving scion traffic. The most common use cases are covered, but solving this lab exercise
	will need more fine grained control than appnet provides.
	*/
	conn, err := appnet.Dial(serverAddr)
	if err != nil {
		fmt.Println("CLIENT: Dial produced an error.", err)
		return
	}
	defer conn.Close()
	n, err := conn.Write(payload)
	if err != nil {
		fmt.Println("CLIENT: Write produced an error.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-written: bytes=%d addr=%s\n", n, serverAddr)
	buffer := make([]byte, meow.MAXBUFFERSIZE)

	// Setting a read deadline makes sure the program doesn't get stuck on waiting for an
	// answer of the server for too long.
	deadline := time.Now().Add(time.Second * 3)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		fmt.Println("CLIENT: SetReadDeadline produced an error.", err)
		return
	}

	nRead, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		fmt.Println("CLIENT: Error reading from connection.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-received: bytes=%d from=%s\n",
		nRead, addr.String())
	var answer string
	json.Unmarshal(buffer[:nRead], &answer)
	fmt.Printf("CLIENT:The answer was: \n%s", answer)

	return
}
