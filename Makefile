
#all: fmt build




build:
	GOOS=linux GOARCH=amd64 go build sip-ban
	#scp ./bin/nasc nas:/apps/nas



