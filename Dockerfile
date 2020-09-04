FROM alpine:3.9

LABEL "maintainer"="Joachim Barheine <joachim.barheine@sap.com>"
LABEL source_repository="https://github.com/sapcc/maia"

ADD build/docker.tar /usr/bin/
ENTRYPOINT ["/usr/bin/maia_linux_amd64"]
