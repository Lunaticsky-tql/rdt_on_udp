#include <fstream>
#include <cassert>
#include "helper.h"

#define PORT 6666
string ADR_ROUTER;
SOCKET socket_sender;
SOCKADDR_IN addr_server;
u_short advertised_window_size;
//give self_window_size nickname N
#define N advertised_window_size
//variables for GBN
u_int base;
u_int nextseqnum;
u_int pkt_total;
bool *acked;

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
    print_message("Advertised window size: " + to_string(advertised_window_size), DEBUG);
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
    //save the window size of the receiver
    advertised_window_size = rcvpkt.head.window_size;
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

void init_SR(u_int pkt_num) {
    base = 0;
    nextseqnum = 0;
    acked = new bool[pkt_num];
}

DWORD WINAPI handle_ACK(LPVOID lpParam) {
    packet rcvpkt;
    while (true) {
        while (!rdt_rcv(rcvpkt) || corrupt(rcvpkt) || !isACK(rcvpkt)) {
            //the packet must be ACK and not corrupt to jump out of the loop
        }
        acked[rcvpkt.head.seq] = true;
        cout<<"Received ACK " + to_string(get_ack_num(rcvpkt))<<endl;
        if (base == pkt_total) {
            return 0;
        }
    }
}

DWORD WINAPI SR(LPVOID lpParam) {
    packet sndpkt=*reinterpret_cast<packet*>(lpParam);
    u_int wait_seq = sndpkt.head.seq;
    int resend_times = 0;
    //start a timer
    clock_t start = clock();
    packet rcvpkt;
    //non-blocking receive here
    while (!acked[wait_seq]) {
        if (timeout(start)) {
            udt_send(sndpkt);
            start = clock();
            if (resend_times > MAX_RESEND_TIMES) {
                print_message("Resend times exceed the limit, there must be something wrong with the network", ERR);
                return 1;
            } else {
                print_message("Resend packet " + to_string(sndpkt.head.seq), WARNING);
                resend_times++;
            }
        }
    }
    //if reach here, the packet is ACKed
    if(wait_seq==base){
        //if the ACKed packet is the base, move the window to the first unACKed packet
        while(acked[base]){
            base++;
        }
    }
    return 0;
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
        init_SR(pkt_total);
        HANDLE handle_ACK_thread = CreateThread(nullptr, 0, handle_ACK, nullptr, 0, nullptr);
        //wasted space but saved time for "shifting" sndpkt window
        clock_t single_file_timer = clock();
        while (base < pkt_total) {
            //send packets
            if (nextseqnum < base + N && nextseqnum < pkt_total) {
                pkt_data_size = min(MAX_SIZE, file_len - nextseqnum * MAX_SIZE);
                packet sndpkt = make_pkt(DATA, nextseqnum, pkt_data_size, file_data + nextseqnum * MAX_SIZE);
                udt_send(sndpkt);
                cout << "Sent packet " + to_string(nextseqnum) << endl;
                nextseqnum++;
                HANDLE SR_handler = CreateThread(nullptr, 0, SR, (LPVOID) &sndpkt, 0, nullptr);
                if(SR_handler==nullptr){
                    print_message("Failed to create thread", ERR);
                    return -1;
                }
            }
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