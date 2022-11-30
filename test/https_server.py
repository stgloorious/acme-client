#!/usr/bin/python

import http.server
import ssl
import sys

httpd = http.server.HTTPServer(('0.0.0.0', 5443), 
        http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile=sys.argv[1], server_side=True)
httpd.serve_forever()
