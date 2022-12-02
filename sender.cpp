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
    return ret != 0;
}

/* check the packet flag and seq */
bool isACK(packet &packet1, int seq) {
    return (packet1.head.flag & ACK) && packet1.head.seq == seq;
}

bool isSYN_ACK(packet &packet1) {
    return (packet1.head.flag & SYN) && (packet1.head.flag & ACK) && packet1.head.seq == 0;
}
bool isFIN_ACK(packet &packet1) {
    return (packet1.head.flag & FIN) && (packet1.head.flag & ACK) && packet1.head.seq == 0;
}

bool wait_ACK0(packet sndpkt) {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || isACK(rcvpkt, 1)||corrupt(rcvpkt)) {
        if (timeout(start)) {
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend packet with seq 0", WARNING);
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
    while (!rdt_rcv(rcvpkt) || isACK(rcvpkt, 0)||corrupt(rcvpkt)) {
        if (timeout(start)) {
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend packet with seq 1", WARNING);
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
    while (!rdt_rcv(rcvpkt) || !isSYN_ACK(rcvpkt)||corrupt(rcvpkt)) {
        if (timeout(start)) {
            packet sndpkt = make_pkt(SYN);
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend handshake packet", WARNING);
                resend_times++;
            }
        }
    }
    return true;

}

bool wait_FIN_ACK() {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || !isFIN_ACK(rcvpkt)||corrupt(rcvpkt)) {
        if (timeout(start)) {
            packet sndpkt = make_pkt(FIN);
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend finish packet", WARNING);
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
    print_message("Read file successfully!", SUC);
    print_message("File length: " + to_string(len), INFO);
    return len;
}

int bye_bye() {
    //send FIN
    packet sndpkt = make_pkt(FIN);
    udt_send(sndpkt);
    if (!wait_FIN_ACK()) {
        print_message("Failed to receive FIN ACK", ERR);
        return 1;
    }
    else
    {
        print_message("Connection closed elegantly, Task finished!", SUC);
        return 0;
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
            //close the connection
            return bye_bye();
        }
        int file_len = get_file_len(file_path);
        string file_name = file_path.substr(file_path.find_last_of('\\') + 1);
        //send file info to router
        packet file_start = make_pkt(FILE_HEAD, 1, file_name.length(), file_name.c_str(), 0, file_len);
        udt_send(file_start);
        // non-blocking receive here, wait for ACK1
        if (!wait_ACK1(file_start)) {
            print_message("Failed to send file name", ERR);
            continue;
        }
        print_message("Ready for sending file!", SUC);
        //read file
        char *file_data = new char[file_len];
        ifstream file(file_path, ios::binary);
        file.read(file_data, file_len);
        file.close();
        //divide file into packets and send them
        int pkt_no = 0;
        int pkt_total = file_len / MAX_SIZE + (file_len % MAX_SIZE? 1: 0);
        int pkt_data_size;
        int stage = SEND0;
        print_message("Total packets: " + to_string(pkt_total), INFO);
        clock_t single_file_timer = clock();
        //send file data
        while(pkt_no<pkt_total)
        {
            pkt_data_size=min(MAX_SIZE,file_len-pkt_no*MAX_SIZE);
            switch(stage)
            {
                case SEND0:
                {
                    packet sndpkt = make_pkt(DATA, 0, pkt_data_size, file_data + pkt_no * MAX_SIZE);
                    udt_send(sndpkt);
                    if (!wait_ACK0(sndpkt)) {
                        print_message("Failed when sending packet number " + to_string(pkt_no), ERR);
                        return 1;
                    }
                    print_message("Sent packet number " + to_string(pkt_no)+" with seq 0", DEBUG);
                    pkt_no++;
                    stage = SEND1;
                    break;
                }
                case SEND1:
                {
                    packet sndpkt = make_pkt(DATA, 1, pkt_data_size, file_data + pkt_no * MAX_SIZE);
                    udt_send(sndpkt);
                    if (!wait_ACK1(sndpkt)) {
                        print_message("Failed when sending packet number " + to_string(pkt_no), ERR);
                        break;
                    }
                    print_message("Sent packet number " + to_string(pkt_no)+" with seq 1", DEBUG);
                    pkt_no++;
                    stage=SEND0;
                    break;
                }
                default:
                    break;
            }
        }
        if(pkt_no==pkt_total)
        {
            print_message("File sent successfully!", SUC);
            print_message("Time used: "+to_string(clock()-single_file_timer)+"ms", INFO);
            // ask whether to send another file
            print_message("Do you want to send another file? (Y/N)", TIP);
            string input;
            getline(cin, input);
            if (input == "Y" || input == "y") {
                continue;
            } else {
                //close connection
                return bye_bye();
            }
        }
        else
        {
            print_message("Error when sending file", ERR);
            return 1;
        }

    }

}