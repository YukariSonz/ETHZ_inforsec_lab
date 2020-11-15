GOFILES=$(wildcard *.go)
COMMON=$(wildcard common/*.go)
BIN=firewall
LIB=lib/firewall.so
INSTALL_BIN=/usr/local/bin/firewall
INSTALL_LIB=/usr/local/lib/firewall.so

default: install

.PHONY: install, bin
install: $(INSTALL_LIB) $(INSTALL_BIN)
bin: $(BIN)

$(INSTALL_BIN): $(BIN)
	sudo cp $< $@
	sudo setcap 'cap_net_admin=+ep' $@
	@ echo "Use the command \"$<\" to run your code."

$(INSTALL_LIB): $(LIB)
	sudo cp $< $@

$(BIN): $(LIB) $(GOFILES) $(COMMON)
	go build -o firewall $(GOFILES)

$(LIB): lib/firewall.go $(COMMON)
	go build -buildmode=plugin -ldflags="-s -w" -o $@ $<

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -f lib/firewall.so
