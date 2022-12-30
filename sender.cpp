#include <fstream>
#include <cassert>
#include "helper.h"
#define PORT 6666
string ADR_ROUTER;
Timer timer;
SOCKET socket_sender;
SOCKADDR_IN addr_server;
u_int advertised_window_size; // advertised window_size size is number of packets
//variables for GBN
u_int base;
u_int nextseqnum;
u_int pkt_total;
//variables for RENO
u_int ssthresh;
u_int cwnd;
u_int dupACKcount;
u_int LastByteSent, LastByteAcked;
u_int window_size;
int RENO_STATE;
bool fast_resend;
packet *sndpkts;

packet make_pkt(u_int flag, u_int seq = 0, u_short data_size = 0, const char *data = nullptr,
                u_int option = 0) {
    packet pkt;
    pkt.head.flag = flag;
    pkt.head.seq = seq;
    pkt.head.data_size = data_size;
    pkt.head.option = option;
    if (data != nullptr) {
        memcpy(pkt.data, data, data_size);
    }
    pkt.head.check_sum = check_sum((u_short *) &pkt, PACKET_SIZE);
    return pkt;
}

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

void print_window_size() {
    print_message("Advertised window_size size: " + to_string(advertised_window_size), DEBUG);
}

void print_window() {
    cout << "[" << state_to_str(RENO_STATE) << "]";
    cout << "[" << LastByteAcked << "|" << LastByteSent << "|" << LastByteAcked + window_size << "]";
    cout << " cwnd:" << cwnd << " ssthresh:" << ssthresh <<" window_size:"<<window_size<< endl;
}

bool is_file_info_ACK(packet &packet1) {
    return (packet1.head.flag & ACK) && (packet1.head.flag & FILE_INFO) && packet1.head.seq == 0;
}

bool isSYN_ACK(packet &packet1) {
    return (packet1.head.flag & SYN) && (packet1.head.flag & ACK) && packet1.head.seq == 0;
}

bool isFIN_ACK(packet &packet1) {
    return (packet1.head.flag & FIN) && (packet1.head.flag & ACK) && packet1.head.seq == 0;
}

bool wait_file_info_ACK(packet sndpkt) {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || corrupt(rcvpkt) || !is_file_info_ACK(rcvpkt)) {
        if (timeout(start)) {
            //resend
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return false;
            } else {
                print_message("Resend file info packet", WARNING);
                resend_times++;
            }
        }
    }
    return true;

}

u_int get_ack_num(packet sndpkt) {
    return sndpkt.head.seq;
}

bool wait_SYN_ACK() {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || !isSYN_ACK(rcvpkt) || corrupt(rcvpkt)) {
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
    //save the window_size size of the receiver
    advertised_window_size = rcvpkt.head.window_size * MSS;
    print_window_size();
    return true;

}

bool wait_FIN_ACK() {
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!rdt_rcv(rcvpkt) || !isFIN_ACK(rcvpkt) || corrupt(rcvpkt)) {
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
    if (!wait_SYN_ACK()) {
        return false;
    }
    print_message("Handshake successfully", SUC);
    return true;
}

u_int get_file_len(const string &file_path) {
    ifstream file(file_path, ios::binary);
    if (!file.is_open()) {
        print_message("File not found", ERR);
        return -1;
    }
    file.seekg(0, ios::end);
    u_int len = file.tellg();
    file.close();
    print_message("Read file successfully!", SUC);
    print_message("File length: " + to_string(len) + " bytes", INFO);
    return len;
}

int bye_bye() {
    //send FIN
    packet sndpkt = make_pkt(FIN);
    udt_send(sndpkt);
    if (!wait_FIN_ACK()) {
        print_message("Failed to receive FIN ACK", ERR);
        return 1;
    } else {
        print_message("Connection closed elegantly, Task finished!", SUC);
        return 0;
    }
}

void init_GBN() {
    base = 0;
    nextseqnum = 0;
}

void init_RENO() {
    //if there is no congestion, we want to send as many packets as possible
    ssthresh = advertised_window_size/2;
    dupACKcount = 0;
    LastByteSent = 0;
    LastByteAcked = 0;
    RENO_STATE = SLOW_START;
    fast_resend = false;
    cwnd = MSS;
    //wasted space but saved time for "shifting" sndpkt window_size
    delete[] sndpkts;
    sndpkts = new packet[pkt_total + 1];

}


DWORD WINAPI handle_ACK(LPVOID lpParam) {
    packet rcvpkt;
    while (true) {
        while (!rdt_rcv(rcvpkt) || corrupt(rcvpkt) || !isACK(rcvpkt)) {
            //the packet must be ACK and not corrupt to jump out of the loop
        }
        // we noticed that once we received a larger ACK,
        // we can safely assume that all the packets before it are ACKed, no matter what happens to the ACK packet itself
        // because the receiver will not send a larger ACK until it receives all the packets before it
//        base = get_ack_num(rcvpkt) + 1;
//        acked[get_ack_num(rcvpkt)] = true;
//        while (acked[base]) {
//            base++;
//        }
        u_int ack_num = get_ack_num(rcvpkt);
        if (ack_num >= base) {
            u_int gap = ack_num - base + 1;
            //update the base and LastByteAcked
            for (int i = 0; i < gap; i++) {
//                cout<<"sndpkts["<<base+i<<"].head.data_size = "<<sndpkts[base+i].head.data_size<<endl;
                LastByteAcked += sndpkts[base + i].head.data_size;
            }
            base = ack_num + 1;
            switch (RENO_STATE) {
                case SLOW_START:
                    cwnd += gap * MSS;
                    dupACKcount = 0;
                    if (cwnd >= ssthresh) {
                        RENO_STATE = CONGESTION_AVOIDANCE;
                    }
                    break;
                case CONGESTION_AVOIDANCE:
                    cwnd += gap * MSS * MSS / cwnd;
                    dupACKcount = 0;
                    break;
                case FAST_RECOVERY:
                    cwnd = ssthresh;
                    RENO_STATE = CONGESTION_AVOIDANCE;
                    dupACKcount = 0;
                    break;
                default:
                    break;
            }
            window_size = min(cwnd, advertised_window_size);
        } else {
            //duplicate ACK
            dupACKcount++;
            if (RENO_STATE == SLOW_START || RENO_STATE == CONGESTION_AVOIDANCE) {
                if (dupACKcount == 3) {
                    //fast retransmit
                    ssthresh = cwnd / 2;
                    cwnd = ssthresh + 3 * MSS;
                    window_size = min(cwnd, advertised_window_size);
                    RENO_STATE = FAST_RECOVERY;
                    print_message("Fast resend"+to_string(ack_num+1), WARNING);
                    //resend the packet
                    udt_send(sndpkts[ack_num + 1]);
                } else {
                    cwnd += MSS;
                }
            }
        }
        cout << "Received ACK " + to_string(get_ack_num(rcvpkt)) + " ";
        print_window();
        if (base == pkt_total) {
            return 0;
        }
        if (base == nextseqnum) {
            timer.stop_timer();
            continue;
        } else {
            timer.start_timer();
        }
    }
}

bool init_socket() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_message("WSAStartup failed!", ERR);
        return false;
    }
    socket_sender = socket(AF_INET, SOCK_DGRAM, 0);
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(PORT);
    return true;
}

void init_IP() {
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
}


string get_file_name(const string &file_path) {
    return file_path.substr(file_path.find_last_of('\\') + 1);
}

int main() {
    assert(init_socket());
    init_IP();
    //set non-blocking socket
    ioctlsocket(socket_sender, FIONBIO, &NON_BLOCK_IMODE);
    //handshake
    if (!handshake()) {
        print_message("Handshake failed!", ERR);
        return -1;
    }
    //begin file sending loop
    while (true) {
        string file_path;
        print_message("Please fill the file path, press ENTER to exit", TIP);
        getline(cin, file_path);
        if (file_path.empty()) {
            //close the connection
            return bye_bye();
        }
        u_int file_len = get_file_len(file_path);
        string file_name = get_file_name(file_path);
        packet file_info = make_pkt(FILE_INFO, 0, file_name.length(), file_name.c_str(), file_len);
        udt_send(file_info);
        // non-blocking receive here, wait for ACK0
        if (!wait_file_info_ACK(file_info)) {
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
        pkt_total = file_len / MAX_SIZE + (file_len % MAX_SIZE ? 1 : 0);
        int pkt_data_size;
        print_message("Total packets: " + to_string(pkt_total), INFO);
        init_GBN();
        init_RENO();
        HANDLE handle_ACK_thread = CreateThread(nullptr, 0, handle_ACK, nullptr, 0, nullptr);
        if (handle_ACK_thread == nullptr) {
            print_message("Failed to create ACK thread", ERR);
            return -1;
        }
        clock_t single_file_timer = clock();
        while (base < pkt_total) {
            //send packets
            window_size = min(cwnd, advertised_window_size);
            if ((LastByteSent - LastByteAcked < window_size) && (LastByteSent < file_len)) {
                pkt_data_size = min(MAX_SIZE, file_len - nextseqnum * MAX_SIZE);
                sndpkts[nextseqnum] = make_pkt(DATA, nextseqnum, pkt_data_size, file_data + nextseqnum * MAX_SIZE);
                udt_send(sndpkts[nextseqnum]);
                cout << "Sent packet " + to_string(nextseqnum) + " ";
                if (base == nextseqnum) {
                    timer.start_timer();
                }
                nextseqnum++;
                LastByteSent += pkt_data_size;
                print_window();
            }
            //handle timeout
            if (timer.timeout()) {
                print_message("Timeout, resend packets from " + to_string(base) + " to " + to_string(nextseqnum - 1),
                              WARNING);
                for (u_int i = base; i < nextseqnum; i++) {
                    udt_send(sndpkts[i]);
                }
                ssthresh = cwnd / 2;
                cwnd = MSS;
                dupACKcount = 0;
                RENO_STATE = SLOW_START;
                timer.start_timer();
            }
            // wait for a while to send next packet (simulating content processing)
            // this is to avoid sending too many packets at once
            Sleep(10);
        }
        if (base == pkt_total) {
            print_message("File sent successfully!", SUC);
            print_message("Time used: " + to_string(clock() - single_file_timer) + "ms", INFO);
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
        } else {
            print_message("Error when sending file", ERR);
            return 1;
        }
    }
}