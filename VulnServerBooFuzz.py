#!/usr/bin/python3
from boofuzz import *
import time
import sys

# Grab banner and use to determine if vulnserver still up
def getBanner(target, log, session, *args, **kwargs):

  # hardcoded banner from vulnserver 
  bannerValue = b"Welcome to Vulnerable Server! Enter HELP for help."
  try:
    # Recieve buffer from the target
    banner = target.recv(10000)
  except:
    # If nothing recieved from the target, print and exit
    print("Couldn't connect the server is down!")
    sys.exit()

  # Write output to our log so that we can retrieve from database
  log.log_check("Receiving banner..")

  # Check if we recieve the banner as a response from the server
  if bannerValue in banner:
    log.log_pass("banner received")
  else:
    # The buffer recieved doesn't containt the banner so we will log failure in db and exit. 
    log.log_fail("No banner received")
    print("No banner received, exiting..")
    sys.exit()

# Main function
def main():

  # create session
  session = Session(sleep_time=1,target=Target(connection=SocketConnection("10.2.170.228", 9999, proto='tcp')),)

  # Setup request
  s_initialize(name="Request")
  with s_block("Host-Line"):
    # Send TRUN command to vulnserver
    s_static("TRUN", name='command name')
    # Add a space after TRUN
    s_delim(" ")
    # After TRUN and the space, add the fuzzing payloads
    s_string("FUZZ",  name='trun variable content')
    # Add a End of Line for Windows
    s_delim("\r\n")

  # Fuzzing
  session.connect(s_get("Request"), callback=getBanner)
  session.fuzz()

if __name__ == "__main__":
	main()
