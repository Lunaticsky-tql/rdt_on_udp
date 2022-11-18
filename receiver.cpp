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

bool handshake(SOCKET *socket, SOCKADDR_IN *address) {
    packet rcvpkt;
    int wrong_times = 0;
    while (true) {
        print_message("Waiting for handshake", INFO);
        if (rdt_rcv(rcvpkt)) {
            if (rcvpkt.head.flag & SYN) {
                packet sndpkt = make_pkt(ACK);
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
//    ioctlsocket(socket_receiver, FIONBIO, &BLOCK_IMODE);
    bind(socket_receiver, (SOCKADDR *) &addr_server, sizeof(addr_server));
    //handshake
    if (!handshake(&socket_receiver, &addr_server)) {
        print_message("Hand shake failed!", ERR);
        return 1;
    }
    print_message("Handshake successfully", SUC);
}