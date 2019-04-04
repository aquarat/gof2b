package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
	"gopkg.in/routeros.v2"
)

var (
	Config = &SystemConfig{
		Address: flag.String("address", "10.0.22.1:8728", "Mikrotik Router IP Address"),
		Username: flag.String("username", "mikrotik-user", "Mikrotik Router Username"),
		Password: flag.String("password", "mikrotik-password", "Mikrotik Router Password"),
		TargetList: flag.String("target-list", "f2blist", "The target IP blocklist on the router."),
		ContainerName: flag.String("container-name", "nginx-proxy", "The name of the container running NGinX."),
		EnableReporting: flag.Bool("report", true, "Report statistics of lines captured at regular interval."),
		ReportingInterval: flag.Int("interval", 60, "The minimum interval between report stats."),
		ConfigFile: flag.String("config", "config.json", "Config file location. Auto-created if it doesn't exist."),
	}

	SpaceStripRegex = regexp.MustCompile(`\s+`)
	BadActors []BadActor
)

// gof2b aims to find bad login attempts on Wordpress sites being accessed behind a dockerised nginx-proxy server.
// It currently (very simplistically) reads the logs of a target container and when a line matching the event in
// in question pops up it logs into the target Mikrotik router and appends the nasty client's IP onto the router's
// target IP blocklist.
//
// This naturally requires a DROP-type rule in the target router's firewall.
// By putting the filtering on the router you save your server some unnecessary traffic and reduce attack vectors.
// Mikrotik routers, by design, are very efficient at packet processing and have spare capacity to do this, so it makes
// sense to me to offload IP blocking onto this machine.
func main() {
	flag.Parse()
	{
		_, err := os.Stat(*Config.ConfigFile)
		if err == nil {
			SecConfig := &SystemConfig{}
			f, err := os.Open(*Config.ConfigFile)
			defer f.Close()
			if err == nil {
				someBytes, err :=  ioutil.ReadAll(f)
				if err == nil {
					CE(json.Unmarshal(someBytes, SecConfig))
				} else {
					CE(err)
					os.Exit(1)
				}
			} else {
				log.Println(err)
				log.Println("Failure while opening existing config file.")
				debug.PrintStack()
				os.Exit(1)
			}
			PopulateConfig(Config, SecConfig)
		} else {
			f, err := os.Create(*Config.ConfigFile)
			defer f.Close()

			if err == nil {
				someBytes, _ := json.Marshal(Config)
				_, err := f.Write(someBytes)
				CE(err)
			} else {
				log.Println(err)
				log.Println("Failure while creating new config file.")
				debug.PrintStack()
			}
		}
	}

	//docker ps | grep nginx-proxy // need to investigate the docker API for a better way
	someBytes, err := exec.Command("/bin/bash", "-c", `docker ps | grep ` + *Config.ContainerName).Output()
	CE(err)

	containerID := strings.Split(string(someBytes), " ")[0]
	log.Println(containerID)

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.WithVersion("1.39"))
	if err != nil {
		panic(err)
	}

	options := types.ContainerLogsOptions{ShowStdout: true, Follow:true}
	out, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		panic(err)
	}

	linesChan := make([]chan string, 1)
	linesChan[0] = make(chan string, 1000)

	outReader := bufio.NewReader(out)

	counterChanIn := make(chan bool, 10000)
	counterChanOut := make(chan bool, 10000)
	counterBadClientList := make(chan bool, 100)
	dieChan := make(chan bool, 1)

	if *Config.EnableReporting {
		go LineCounter(counterChanIn, counterChanOut, counterBadClientList, dieChan)
	}

	go func() {
		for {
			str, err := outReader.ReadString('\n')
			if err != nil {
				log.Fatal("Read Error:", err)
				os.Exit(1)
			}
			linesChan[0] <- str
			counterChanIn <- false
		}
	}()

	// nginx.1     | some-website.co.za 139.59.82.21 - - [28/Mar/2019:21:23:11 +0000] "GET /wp-login.php HTTP/1.1" 200 1592 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0"
	// nginx-proxy        | nginx.1     | some-website.co.za 185.211.245.199 - - [22/Mar/2019:21:05:12 +0000] "POST /wp-login.php HTTP/1.1" 500 595 "https://your-website.co.za/wp-login.php" "Mozilla/5.0 (Windows NT 5.1; WOW64; x64) AppleWebKit/532.93.46 (KHTML, like Gecko) Chro
	//me/57.4.0548.5810 Safari/534.54 OPR/44.6.1260.6523"
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill)

	for {
		select {
		case newLine := <-linesChan[0]:
			newLine = stripDuplicateWS(newLine)

			counterChanOut <- false
			if strings.Contains(newLine, "POST /wp-login.php") &&
				!strings.Contains(newLine, "302") { // 302 is a good redirect lol, a bad attempt results in a 200
				// bad client...
				toks := strings.Split(newLine, " ")
				badIP := ""
				if len(toks) > 3 {
					badIP = toks[3]
				}

				if appendBadIP(badIP) == 3 {
					///kill it
					counterBadClientList <- false
					log.Println("BAD IP ", badIP)
					BanIP(badIP)
				}
			}
			break
		case <-sigc:
			os.Exit(0)
		}
	}
}

// Very clumsily checks if config flags have been set on the command line and if so overrides the supplied config.
// There's almost certainly a sexier, cleaner way of doing this.
func PopulateConfig(defaultConfig, newConfig *SystemConfig) {
	flag.Visit(func(f *flag.Flag) {
		log.Println("Flag visited ", f.Name)
		switch f.Name {
		case "address" :
			newConfig.Address = defaultConfig.Address
			break
		case "username" :
			newConfig.Username = defaultConfig.Username
			break
		case "password" :
			newConfig.Password = defaultConfig.Password
			break
		case "target-list" :
			newConfig.TargetList = defaultConfig.TargetList
			break
		case "container-name":
			newConfig.Username = defaultConfig.ContainerName
			break
		case "report" :
			newConfig.EnableReporting = defaultConfig.EnableReporting
			break
		case "interval" :
			newConfig.ReportingInterval = defaultConfig.ReportingInterval
			break
		}
	},
	)

	someBytes, _ := json.Marshal(defaultConfig)
	log.Println(string(someBytes))
	someBytes, _ = json.Marshal(newConfig)
	log.Println(string(someBytes))

	Config = newConfig
}

// Provides a go-routine for counting (and reporting) processing stats. Very useful for initial syncs.
func LineCounter(counterChanIn, counterChanOut, badClientList, die chan bool) {
	var (
		badClientListCounter int64 = 0
		counterIn int64 = 0
		counterOut int64 = 0
		counterInLast int64 = 0
		counterOutLast int64 = 0
	)

	ticky := time.NewTicker(time.Second * time.Duration(int64(*Config.ReportingInterval)))
	for {
		select{
		case <- ticky.C:
			if counterInLast != counterIn || counterOutLast != counterOut {
				log.Println("Lines : In ", counterIn, " Out ", counterOut)
				counterOutLast = counterOut
				counterInLast = counterIn
			}
			break
		case <-counterChanIn: counterIn++
			break
		case <-counterChanOut: counterOut++
			break
		case <-badClientList: badClientListCounter++
			break
		case <- die: return
		}
	}
}

// Strips duplicate spaces from strings.
func stripDuplicateWS(a string) (out string) {
	return SpaceStripRegex.ReplaceAllString(a, " ")
}

// Bans an IP on the target router by adding the IP to the target address list.
func BanIP(ip string) {
	c, err := routeros.Dial(*Config.Address, *Config.Username, *Config.Password)
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.Run(`/ip/firewall/address-list/add`, "=list=" + *Config.TargetList, `=address=` + ip)
	if err != nil {
		log.Fatal(err)
	}
}

// Appends the Bad IP to the application's internal address list for counting purposes.
func appendBadIP(ip string) (count int){
	if len(ip) < 2 { // eg. 0.11.0.12
		return
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return
	}

	for i, j := range BadActors {
		if j.IP == ip {
			BadActors[i].Count = BadActors[i].Count + 1
			BadActors[i].LastSeen = time.Now()

			return j.Count
		}
	}

	BadActors = append(BadActors, BadActor{IP: ip, Count: 1, LastSeen: time.Now()})
	count = 1

	return
}

// A generic error checking function.
func CE(e error) {
	if e != nil {
		log.Println(e)
		debug.PrintStack()
	}
}