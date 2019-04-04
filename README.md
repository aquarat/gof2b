# gof2b

gof2b is a simple fail2ban clone that seeks to leverage a Mikrotik gateway router as a means of blocking traffic from misbehaving client IPs. It specifically monitors a docker container running jwilder's nginx reverse proxy and looks for failed attempts to login using wp-login.php.

I've noticed that my Wordpress sites regularly have brute-force login attempts made against them. The bad clients in these cases execute attempts that (1) well-placed delays between attempts, (2) do a GET before a POST, (3) only attempt 4 logins from one IP, (4) use many IPs. These seem to be tailored to avoid fail2ban's default settings. Nasty.

go2fb is highly simplistic and could do with some extra cleaning up/additional functionality. It only works for Wordpress sites currently.

### Building
go get -v github.com/aquarat/gof2b

if you want arm64 : 
GOARCH=arm64 go build github.com/aquarat/gof2b

### Running

With no command-line arguments, gof2b will look for a config.json file. If it doesn't find it, it will create one with default values. Subsequent executions will read config from this file first and then override values with command-line arguments. Command-line arguments are never written back to the config.json file.
