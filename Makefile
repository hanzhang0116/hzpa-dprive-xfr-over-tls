# Draft Makefile. You will need:
# - mmark (https://github.com/mmarkdown/mmark)
# - xml2rfc with v3 support (https://xml2rfc.tools.ietf.org/)

DRAFT=draft-ietf-dprive-xfr-over-tls
VERSION=12

XML=$(DRAFT).xml
HTML=$(DRAFT)-$(VERSION).html
TXT=$(DRAFT)-$(VERSION).txt

.PHONY: clean

all: $(HTML) $(TXT) 

$(XML): $(DRAFT).md; mmark $< > $@

$(HTML): $(XML) ; xml2rfc --html -o $@ $<
$(TXT): $(XML) ; xml2rfc --text -o $@ $<

clean: ; rm $(XML) $(HTML) $(TXT)