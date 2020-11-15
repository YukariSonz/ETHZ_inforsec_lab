package meow

import (
	"encoding/json"
)

/*
// meow
*/

const MAXBUFFERSIZE = 8192
const SERVER_IP = "10.100.1.2"

var SERVER_PORTS []uint64 = []uint64{8090, 8091}

// Supported Queries
type Query string

const (
	First  Query = "1"
	Second Query = "2"
	Third  Query = "3"
)

// Message format
type RequestHeader struct {
	Id    uint64
	Flags []string
}

type RequestBody struct {
	Query Query
}

type request struct {
	H RequestHeader
	B RequestBody
}

// The answer format of the server is a string

// Constructor for Request
func NewRequest(q Query, options ...func(*JsonRequest)) *JsonRequest {
	header := RequestHeader{
		Id:    0,
		Flags: make([]string, 0),
	}
	body := RequestBody{
		Query: q,
	}
	internalRequest := request{
		H: header,
		B: body,
	}
	answ := JsonRequest{
		jsonD: internalRequest,
	}
	for _, option := range options {
		option(&answ)
	}
	return &answ
}

// Setters
func SetID(id uint64) func(r *JsonRequest) {
	return func(r *JsonRequest) {
		r.jsonD.H.Id = id
	}
}

// Hint: The supported flags are inspired by typical flags used with command-line applications
func AddFlag(flag string) func(r *JsonRequest) {
	return func(r *JsonRequest) {
		r.jsonD.H.Flags = append(r.jsonD.H.Flags, flag)
	}
}

// Getters
func (r *JsonRequest) ID() uint64 {
	return r.jsonD.H.Id
}

func (r *JsonRequest) Flags() []string {
	return r.jsonD.H.Flags
}

func (r *JsonRequest) Query() Query {
	return r.jsonD.B.Query
}

// Serialization
type JsonRequest struct {
	jsonD request
}

func (jr *JsonRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(&request{
		H: jr.jsonD.H,
		B: jr.jsonD.B,
	})
}
