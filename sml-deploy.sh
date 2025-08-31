#!/bin/bash

cd /var/www/html/sml-data-download-api
go build -o sml-data
pm2 start sml-data --name sml-data-api