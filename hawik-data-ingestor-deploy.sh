#!/bin/bash

cd /var/www/html/sml-data-download-apihawik-data-ingestor
go build -o hawik-data-ingestor
pm2 start hawik-data-ingestor --name hawik-data-ingestor