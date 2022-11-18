#include <fstream>
#include "helper.h"

#define PORT 6666
string ADR_ROUTER;

SOCKET socket_sender;
SOCKADDR_IN addr_server;


void udt_send(packet packet1) {
    sendto(socket_sender, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, sizeof(addr_server));

}

bool rdt_rcv(packet &packet1) {
    int len = sizeof(addr_server);
    int ret = recvfrom(socket_sender, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, &len);
    if (ret == SOCKET_ERROR) {
        return false;
    }
    if (corrupt(packet1)) {
        print_message("Receive a corrupt packet", ERR);
        cout<<packet1.head.check_sum<<endl;
        cout<<packet1.head.flag<<endl;
        return false;
    }
    return ret != 0;
}

/* check the packet flag and seq */
bool isACK(packet &packet1, int seq) {
    return (packet1.head.flag & ACK) && packet1.head.seq == seq;

}

bool handshake(SOCKET *pInt, SOCKADDR_IN *pIn) {
    //as the transmitting is single-direction, so we only need to "shake" two times
    packet sndpkt = make_pkt(SYN);
    udt_send(sndpkt);
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    while (!rdt_rcv(rcvpkt)) {
        if (timeout(start)) {
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend packet", INFO);
                resend_times++;
            }
        }
    }
    if (isACK(rcvpkt, 0)) {
        print_message("Handshake successfully", SUC);
        return true;
    } else {
        print_message("Receive wrong packet", ERR);
        return false;
    }
}


int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_message("WSAStartup failed!", ERR);
        return 1;
    }
    socket_sender = socket(AF_INET, SOCK_DGRAM, 0);
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(PORT);
    //it can do nothing but wait for us to start the connection manually
    print_message("Please input the router's IP address, press ENTER to use default address: " + ADR_ROUTER, TIP);
    string input_router;
    getline(cin, input_router);
    if (!input_router.empty()) {
        ADR_ROUTER = input_router;
    } else {
        ADR_ROUTER = LOCALHOST;
    }
    addr_server.sin_addr.S_un.S_addr = inet_addr(ADR_ROUTER.c_str());
    print_message("Router IP: " + ADR_ROUTER, INFO);
    //set non-blocking socket
    ioctlsocket(socket_sender, FIONBIO, &NON_BLOCK_IMODE);
    //handshake
    if (!handshake(&socket_sender, &addr_server)) {
        print_message("Handshake failed!", ERR);
        return 1;
    }
    print_message("Handshake successfully", SUC);
    while(true) {
        string input;
        print_message("Please input the file path, press ENTER to exit", TIP);
        getline(cin, input);
        if (input.empty()) {
            break;
        }
        ifstream file(input, ios::binary);
        if (!file.is_open()) {
            print_message("File not found", ERR);
            continue;
        }
        //send file name to router

    }

}