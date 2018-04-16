from scapy.all import *
from twilio.rest import Client

print("Listening...\n")

account = "twilio_acct"
token = "twilio_token"
client = Client(account, token)


def arp_display(pkt):
    if pkt[ARP].op == 1:
        if pkt[ARP].hwsrc == "mac_address":
            print("ARP Probe from: " + pkt[ARP].hwsrc + "\n")
            message = client.messages.create(
                to="#",
                from_="twilio_#",
                body="I NEED HELP!")
            print("Message sent \n")


print(sniff(prn=arp_display, filter="arp", store=0, count=10))
