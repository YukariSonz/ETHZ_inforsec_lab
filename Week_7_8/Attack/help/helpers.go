package help

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// Constants used by the helpers:
const (
	DISPATCHER_PORT        = 30041
	DISPATCHER_CONFIG_PATH = "/etc/scion/gen/dispatcher/disp.toml"
	PORT_YAML_PATH         = "port.yaml"
)

type Port struct {
	Port string `yaml:"victimPort"`
}

/* loadVictimPort loads the port defined in port.yaml. Remote victim will multiplex on these ports
when reporting the attack volume back to you.
*/
func LoadVictimPort() int {
	var p *Port
	yamlFile, err := ioutil.ReadFile(PORT_YAML_PATH)
	if err != nil {
		log.Printf("Error reading port: %v", err)
		return 0
	}
	err = yaml.Unmarshal(yamlFile, &p)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
		return 0
	}
	port, err := strconv.Atoi(p.Port)
	if err != nil {
		log.Printf("Conversion error: %v", err)
		return 0
	}
	return port
}

// You may use these helpers in your solution:

/* ParseDispatcherSocketFromConfig finds the path of the dispatcher socket from the config file.
 */
func ParseDispatcherSocketFromConfig() (string, error) {
	file, err := os.Open(DISPATCHER_CONFIG_PATH)
	if err != nil {
		return "", err
	}
	// Read file line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var socket = ""
	for scanner.Scan() {
		// Find Socket
		line := scanner.Text()
		if strings.Contains(line, "application_socket") {
			socket_start_idx := strings.Index(line, `"`) + 1
			socket = line[socket_start_idx : len(line)-1]
		}
	}
	return socket, nil
}

/* ParseSCIONDAddrFromConfig finds the address of the scion daemon from the config file
 */
func ParseSCIONDAddrFromConfig() (string, error) {
	file, err := os.Open(SciondConfigPath())
	if err != nil {
		return "", err
	}
	// Read file line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var addr = ""
	for scanner.Scan() {
		// Find addr
		line := scanner.Text()
		if strings.Contains(line, "address") {
			addr_start_idx := strings.Index(line, `"`) + 1
			addr = line[addr_start_idx : len(line)-1]
		}
	}
	return addr, nil
}

/* FindLocalISD extracts the local Isolation Domain number from the folder hierarchy.
The configuration root is assumed to be "/etc/scion/gen"
Returns an empty string and non-nil error if unsuccessful.
*/
func FindLocalISD() (string, error) {
	dir_root := "/etc/scion/gen/"
	files, err := ioutil.ReadDir(dir_root)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if strings.Contains(f.Name(), "ISD") {
			return strings.ReplaceAll(f.Name(), "ISD", ""), nil
		}
	}
	return "", errors.New("Not found")
}

/* FindLocalISDFolder extracts the local Isolation Domain folder from the folder hierarchy.
The configuration root is assumed to be "/etc/scion/gen"
Returns an empty string and non-nil error if unsuccessful.
*/
func FindLocalISDFolder() (string, error) {
	dir_root := "/etc/scion/gen/"
	files, err := ioutil.ReadDir(dir_root)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if strings.Contains(f.Name(), "ISD") {
			return f.Name(), nil
		}
	}
	return "", errors.New("Not found")
}

/* FindLocalIA extracts the local scion Internet Address from the folder hierarchy.
The configuration root is assumed to be "/etc/scion/gen"
Returns an empty string and non-nil error if unsuccessful.
*/
func FindLocalAs() (string, error) {
	dir_root := "/etc/scion/gen"
	isd, err := FindLocalISDFolder()
	if err != nil {
		return "", err
	}
	isd_dir := filepath.Join(dir_root, isd)
	files, err := ioutil.ReadDir(isd_dir)
	if err != nil {
		return "", err
	}
	// We are assuming that there is only one folder in here.
	noAS := strings.ReplaceAll(files[0].Name(), "AS", "")
	return strings.ReplaceAll(noAS, "_", ":"), nil
}

/* FindLocalAsFolder() extracts the local SCION Internet Address folder from the folder hierarchy.
The configuration root is assumed to be "/etc/scion/gen"
Returns an empty string and non-nil error if unsuccessful.
*/
func FindLocalAsFolder() (string, error) {
	dir_root := "/etc/scion/gen"
	isd, err := FindLocalISDFolder()
	if err != nil {
		return "", err
	}
	isd_dir := filepath.Join(dir_root, isd)
	files, err := ioutil.ReadDir(isd_dir)
	if err != nil {
		return "", err
	}
	// We are assuming that there is only one folder in here.
	return files[0].Name(), nil
}

/* SciondConfigPath constructs the local sciond configuration path.
The configuration root is assumed to be "/etc/scion/gen"
Returns an empty string if unsuccessful.
*/
func SciondConfigPath() string {
	isd, err := FindLocalISDFolder()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	ia, err := FindLocalAsFolder()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return filepath.Join("/etc/scion/gen/", isd, ia, "endhost/sd.toml")
}
