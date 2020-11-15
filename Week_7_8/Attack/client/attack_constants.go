package client

import "time"

//
// Constants related to the lab setup:
//
const (
	ATTACK_SECONDS = 10
	// This is how long the victim will measure incoming packets. It is recommended to
	// terminate your attack after the measurement period such that the remote victim does not confuse
	// the attack boundaries. During grading, your client will be stopped automatically after this time.
	ATTACK_TIME        = ATTACK_SECONDS * time.Second
	VICTIM_SCION_ADDR  = "17-ffaa:0:1115" // ISL-Victim
	VICTIM_IP          = "127.0.0.1"
	ROOT_NS_IP_STUDENT = "10.200.1.1"
	ATTACK_IP          = "10.200.1.2"
	// IP of attack_ns in the default namespace, send to this address to reach the default namespace
	// used by the local victim
	LOCAL_REFLECTION_IP = "10.100.1.1"
)
