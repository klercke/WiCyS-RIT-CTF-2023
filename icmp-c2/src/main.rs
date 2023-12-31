use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, icmp_packet_iter};
use pnet::util::checksum;
use std::env;

const PASSWORD: &str = "flag plz :)";
const RESPONSE_CORRECT: &str = "WCS{7c2b749cc9bf114830c62077802ac6c4}";
const RESPONSE_INCORRECT: &str = "ERR: Unknown command.";

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                
                // Wait for an echo request
                match packet.get_icmp_type() {
                    pnet::packet::icmp::IcmpType(8) => {},
                    _ => continue
                }

                // Convert the payload from the ICMP packet to a String.
                // The slicing is to strip out leading characters (the ID and sequence words)
                // Trim any null characters off the end as well.
                // Finally, make sure to remove the newline at the end.
                let payload = String::from_utf8_lossy(&packet.payload()[4..]).replace('\n', "");

                // Rename packet so it's easier to understand its purpose
                let request_packet = packet;

                // Initialize response_packet
                let mut packet_vector: Vec<u8> = 
                if PASSWORD.to_string().eq(&payload.to_string()) {
                    println!("Received flag request from {} :)", addr);
                    vec![0; 8 + RESPONSE_CORRECT.as_bytes().len()]
                }
                else {
                    println!("Received ICMP packet from {} with wrong payload ({}) :(", addr, payload);
                    vec![0; 8 + RESPONSE_INCORRECT.as_bytes().len()]
                };
                let mut response_packet = MutableEchoReplyPacket::new(&mut packet_vector).unwrap();

                // Get the ICMP ID from the incoming packet by converting two u8s to a u16, then set that as the ID on the outgoing packet
                let request_packet_id = ((request_packet.packet()[4] as u16) << 8) | request_packet.packet()[5] as u16;
                response_packet.set_identifier(request_packet_id);

                // Get the ICMP sequence number from the incoming packet the same way we got the ID
                let request_packet_sequence = ((request_packet.packet()[6] as u16) << 8) | request_packet.packet()[7] as u16;
                response_packet.set_sequence_number(request_packet_sequence);

                // Set the payload
                if PASSWORD.to_string().eq(&payload.to_string()) {
                    response_packet.set_payload(RESPONSE_CORRECT.as_bytes());
                }
                else {
                    response_packet.set_payload(RESPONSE_INCORRECT.as_bytes());
                }

                // Make sure the checksum is set to 0 before calculating the checksum (https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_checksum)
                // This is not actually necessary since the next line specifically ignores the checksum word, but I'm not deleting it because that's a fun tidbit of info
                response_packet.set_checksum(0);
                response_packet.set_checksum(checksum(response_packet.packet(), 0));

                // Send the packet
                match tx.send_to(response_packet, addr) {
                    Ok(_) => (),
                    Err(e) => panic!("failed to send packet: {}", e),
                }    
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }   
        }
    }
}
