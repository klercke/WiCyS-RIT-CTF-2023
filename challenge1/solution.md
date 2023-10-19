# IC2MP: Challenge 1

## Solution

After opening the pcap file in a tool such as Wireshark, one will find "normal" user traffic. After the user downloads some files, we see some ICMP traffic. This comes from the "malware" on their computer (I did download actual malware when creating this pcap, but the ICMP traffic was all manual ;)). Wireshark may flag one echo request packet (54687) with "no response found!", despite the fact that that packet does have a reply attached to it (54873). If we look at the ICMP payloads of these two packets, we see "flag plz :)" and "WCS{fe107f14a63f30efc7edb90f18c40b5a}", respectively. This is our flag.

Alternatively, one can just run "strings challenge1/chall.pcapng | grep WCS". This will also find the flag. While not the intended solution, I still consider this valid since it is effectively just using another tool to speed up the search.