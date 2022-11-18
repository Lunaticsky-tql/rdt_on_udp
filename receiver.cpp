#include <fstream>
#include "helper.h"

#define PORT 8888
string ADR_ROUTER = LOCALHOST;
int addr_len;
SOCKET socket_receiver;
SOCKADDR_IN addr_server;

void udt_send(packet packet1) {
    sendto(socket_receiver, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, addr_len);
}

bool rdt_rcv(packet &packet1) {
    int len = sizeof(addr_server);
    int ret = recvfrom(socket_receiver, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, &len);
    if (ret == SOCKET_ERROR) {
        return false;
    }
    if (corrupt(packet1)) {
        print_message("Receive a corrupt packet", ERR);
        return false;
    }
    return ret != 0;
}
bool has_seq0(packet &packet1) {
    return packet1.head.seq == 0;
}
bool has_seq1(packet &packet1) {
    return packet1.head.seq == 1;
}
bool isSYN(packet &packet1) {
    return (packet1.head.flag & SYN);
}

bool handshake() {
    packet rcvpkt;
    int wrong_times = 0;
    while (true) {
        print_message("Waiting for handshake", INFO);
        //blocking receive here
        if (rdt_rcv(rcvpkt)) {
            if (isSYN(rcvpkt)) {
                packet sndpkt = make_pkt(ACK_SYN);
                udt_send(sndpkt);
                return true;
            } else {
                print_message("Received wrong packet", ERR);
                //discard the packet and continue to wait
                if (wrong_times > MAX_WRONG_TIMES) {
                    print_message("Wrong times exceed the limit, there must be something wrong with the network", ERR);
                    return false;
                } else {
                    wrong_times++;
                    continue;
                }
            }
        }
    }
}



int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_message("WSAStartup failed!", ERR);
        return 1;
    }
    socket_receiver = socket(AF_INET, SOCK_DGRAM, 0);
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(PORT);
    //we assume the router is on the localhost
    addr_server.sin_addr.S_un.S_addr = inet_addr(LOCALHOST);
    addr_len = sizeof(addr_server);
    print_message("Receiver is running on localhost...", INFO);
    //set blocking socket
    //ioctlsocket(socket_receiver, FIONBIO, &BLOCK_IMODE);
    bind(socket_receiver, (SOCKADDR *) &addr_server, sizeof(addr_server));
    //handshake
    if (!handshake()) {
        print_message("Hand shake failed!", ERR);
        return 1;
    }
    print_message("Handshake successfully", SUC);
    while (true) {
        clock_t wait_file_start = clock();
        packet rcvpkt;
        //change to non-blocking socket
        ioctlsocket(socket_receiver, FIONBIO, &NON_BLOCK_IMODE);
        char *file_buffer;
        while(!rdt_rcv(rcvpkt))
        {
            if (wait_file_timeout(wait_file_start)) {
                print_message("Timeout, no file received", ERR);
                return 1;
            }
        }
        if(has_seq1(rcvpkt))
        {
            print_message("Ready to receive files", SUC);
            print_message("File name: " + string(rcvpkt.data), INFO);
            print_message("File size: " + to_string(rcvpkt.head.option), INFO);
            file_buffer = new char[rcvpkt.head.option];
        }
        else if(isSYN(rcvpkt))
        {
            //if the ack is lost, the sender will resend the SYN packet
            print_message("Received a SYN packet, reset the timer", INFO);
            continue;
        }
        else
        {
            print_message("Received a wrong packet", ERR);
            continue;
        }
        return 0;
    }
}