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
        cout << packet1.head.check_sum << endl;
        cout << packet1.head.flag << endl;
        return false;
    }
    return ret != 0;
}

/* check the packet flag and seq */
bool isACK(packet &packet1, int seq) {
    return (packet1.head.flag & ACK) && packet1.head.seq == seq;

}

bool isSYN_ACK(packet &packet1) {
    return (packet1.head.flag & SYN) && (packet1.head.flag & ACK) && packet1.head.seq == 0;
}

bool wait_ACK0(packet sndpkt) {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || isACK(rcvpkt, 1)) {
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
        if (isACK(rcvpkt, 1)) {
            print_message("Received ACK1, discard it", DEBUG);
        }
    }
    return true;

}

bool wait_ACK1(packet sndpkt) {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || isACK(rcvpkt, 0)) {
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
        if (isACK(rcvpkt, 0)) {
            print_message("Received ACK0, discard it", DEBUG);
        }
    }
    return true;

}

bool wait_SYN_ACK() {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || !isSYN_ACK(rcvpkt)) {
        if (timeout(start)) {
            packet sndpkt = make_pkt(SYN);
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
    return true;

}

bool handshake() {
    //as the transmitting is single-direction, so we only need to "shake" two times
    packet sndpkt = make_pkt(SYN);
    udt_send(sndpkt);
    return wait_SYN_ACK();
}

int get_file_len(const string &file_path) {
    ifstream file(file_path, ios::binary);
    if (!file.is_open()) {
        print_message("File not found", ERR);
        return -1;
    }
    file.seekg(0, ios::end);
    int len = file.tellg();
    file.close();
    return len;
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
    if (!handshake()) {
        print_message("Handshake failed!", ERR);
        return 1;
    }
    print_message("Handshake successfully", SUC);
    while (true) {
        string file_path;
        print_message("Please fill the file path, press ENTER to exit", TIP);
        getline(cin, file_path);
        if (file_path.empty()) {
            break;
        }
        int file_len = get_file_len(file_path);
        //get file name from file path
        string file_name = file_path.substr(file_path.find_last_of('\\') + 1);
        //send file name to router
        packet file_start = make_pkt(FILE_HEAD, 1, file_name.length(), file_name.c_str(), 0, file_len);
        udt_send(file_start);
        clock_t start = clock();
        // non-blocking receive here, wait for ACK
        while (!rdt_rcv(file_start)) {
            if (timeout(start)) {
                udt_send(file_start);
                start = clock();
            }
        }
        return 0;

    }

}