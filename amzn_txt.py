from scapy.all import *
from twilio.rest import Client

print("Listening...\n")

account = "AC5c1ecd299238426828c355d1a21513ec"
token = "2418b655ee3810993b6e94b74d0d496f"
client = Client(account, token)


def arp_display(pkt):
    if pkt[ARP].op == 1:
        if pkt[ARP].hwsrc == "44:32:c8:f3:10:07":
            print("ARP Probe from: 44:32:c8:f3:10:07" + pkt[ARP].hwsrc + "\n")
            message = client.messages.create(
                to="+17073732510",
                from_="+14153606734",
                body="I NEED HELP!")
            print("Message sent \n")


print(sniff(prn=arp_display, filter="arp", store=0, count=10))
