# IC2MP: Challenge 2

## Solution

After solving challenge 1, one knows the address of the C2 server in question (c2.pingdynasty.net / 172.104.31.204) AND the ICMP payload necessary to get the server to respond ("flag plz :)"). The participant simply needs to send an ICMP echo request packet with the correct payload to the C2 server. One way to do this would be to create a file called "payload.txt" with the contents "flag plz :)\n" in the current working directory and use the following hping3 command:

```sudo hping3 --icmp 172.21.117.198 -E payload.txt -d 1500```

Luckily, our PingDynasty hackers were kind enough to strip the blank bytes off of the end of the payload, so the data size arguement can really be anything large enough to hold the entire payload, but small enough to fit in the payload of an ICMP packet.

One will likely need a packet capture running locally to see the response. I suggest ```sudo tcpdump -ntvvAi eth0 icmp```, but Wireshark with a capture OR display filter of simply "icmp" will also work.

If an echo request packet with any other payload is sent to the C2 server, the payload of the response will be "ERR: Unknown command". It does NOT echo the payload of the incoming packet. This is an intentional choice made to give a hint that one is on the right track with checking the payload of the response. If this were an actual C2 server, I would probably try to cover my tracks a bit better (and maybe not put "C2" in the URL) ;).