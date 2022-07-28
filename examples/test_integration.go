package main

import (
	"log"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxDifference = 10

func main() {
	out, err := exec.Command("./client").Output()
	if err != nil {
		log.Fatal(err)
	}
	remote, err := strconv.Atoi(strings.Split(string(out), " ")[1])
	if err != nil {
		log.Fatal(err)
	}

	remote = remote / 1e6
	local := int(time.Now().Unix())

	log.Printf("remote %v local %v difference %v\n", remote, local, remote-local)

	if math.Abs(float64(remote-local)) > maxDifference {
		log.Fatal("difference too large")
	}
}
