#!/usr/bin/python3
from boofuzz import *
import sys
from bs4 import BeautifulSoup
import requests
import re

# Grab banner and use to determine if vulnserver still up
def getBanner(target, log, session, *args, **kwargs):
  banner = "Welcome to Home"
  url = 'http://127.0.0.1/index.html'
  try:
    log.log_check("Requesting Content")
    page = requests.get(url, timeout=5)
    soup = BeautifulSoup(page.text, 'html.parser')
    results = soup.body.find_all(string=re.compile('.*{0}.*'.format(banner)), recursive=True)
  except:
    # If nothing recieved from the target, print and exit
    log.log_check("Can't Recive Banner")
    sys.exit()

  #Write output to our log so that we can retrieve from database
  log.log_check("Receiving banner..")
  log.log_pass(len(results))
  # Check if we recieve the banner as a response from the web
  if len(results) > 0:
    log.log_pass("banner received")
  else:
    log.log_fail("No banner received")
    print("No banner received, exiting..")
    sys.exit()

# Main function
def main():
  # create session
  session = Session(sleep_time=1,target=Target(connection=SocketConnection("127.0.0.1", 80, proto='tcp')),crash_threshold_request=1, crash_threshold_element=1,)

  s_initialize(name="Request")
  with s_block("Request-Line"):
    s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
    s_delim(" ", name='space-1')
    s_string("/index.html", name='Request-URI')
    s_delim(" ", name='space-2')
    s_string('HTTP/1.1', name='HTTP-Version')
    s_static("\r\n", name="Request-Line-CRLF")
  s_static("\r\n", "Request-CRLF")

  # Fuzzing
  session.connect(s_get("Request"), callback=getBanner)
  session.fuzz()

if __name__ == "__main__":
	main()
