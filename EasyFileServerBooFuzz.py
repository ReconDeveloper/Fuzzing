#!/usr/bin/python3
from boofuzz import *
import time
import sys

# Main function
def main():

  # create session
  session = Session(sleep_time=1,target=Target(connection=SocketConnection("10.2.170.214", 80, proto='tcp')),crash_threshold_request=1, crash_threshold_element=1,)

  s_initialize(name="Request")
  with s_block("Request-Line"):
    s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
    s_delim(" ", name='space-1', fuzzable = False)
    s_string("/index.html", name='Request-URI')
    s_delim(" ", name='space-2', fuzzable = False)
    s_string('HTTP/1.1', name='HTTP-Version', fuzzable = False)
    s_static("\r\n", name="Request-Line-CRLF")
  s_static("\r\n", "Request-CRLF")

  # Fuzzing
  session.connect(s_get("Request"))
  session.fuzz()

if __name__ == "__main__":
	main()
