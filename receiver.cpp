#include <fstream>
#include <io.h>
#include <cassert>
#include "helper.h"

#define PORT 8888
string ADR_ROUTER = LOCALHOST;

int addr_len;
SOCKET socket_receiver;
SOCKADDR_IN addr_server;
u_short self_window_size = 10;
u_int expectedseqnum = 0;


packet make_pkt(u_int flag, u_int seq = 0, u_short data_size = 0, const char *data = nullptr,
                u_int option = 0) {
    packet pkt;
    pkt.head.flag = flag;
    pkt.head.seq = seq;
    pkt.head.window_size = self_window_size;
    pkt.head.data_size = data_size;
    pkt.head.option = option;
    if (data != nullptr) {
        memcpy(pkt.data, data, data_size);
    }
    pkt.head.check_sum = check_sum((u_short *) &pkt, PACKET_SIZE);
    return pkt;
}

void print_window_size() {
    print_message("Window size: " + to_string(self_window_size),DEBUG);
}

void udt_send(packet packet1) {
    sendto(socket_receiver, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, addr_len);
}

bool rdt_rcv(packet &packet1) {
    clock_t wait_start = clock();
    int ret = recvfrom(socket_receiver, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, &addr_len);
    while (ret == SOCKET_ERROR || ret == 0) {
        if (wait_file_timeout(wait_start)) {
            print_message("Timeout, no packet received", ERR);
            return false;
        }
        ret = recvfrom(socket_receiver, (char *) &packet1, PACKET_SIZE, 0, (SOCKADDR *) &addr_server, &addr_len);
    }
    return true;
}


bool handshake() {
    packet rcvpkt;
    int wrong_times = 0;
    while (true) {
        print_message("Waiting for handshake", INFO);
        //blocking receive here
        if (rdt_rcv(rcvpkt)) {
            if (isSYN(rcvpkt) && not_corrupt(rcvpkt)) {
                packet sndpkt = make_pkt(ACK_SYN);
                udt_send(sndpkt);
                print_message("Handshake successfully", SUC);
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
        } else {
            //timeout
            print_message("Handshake Timeout", ERR);
            return false;
        }
    }
}

string get_file_path(const string &file_name) {
    string file_path = string(getcwd(nullptr, 0));
    file_path = file_path.substr(0, file_path.find_last_of('\\'));
    file_path += "\\receiver_files\\" + file_name;
    return file_path;
}

bool is_file_info_pkt(packet packet1) {
    return (packet1.head.flag == FILE_INFO) && (packet1.head.seq == 0);
}

bool ready_for_file(string &file_name, u_int &file_size) {
    packet rcvpkt;
    print_message("Waiting for file info", INFO);
    if (rdt_rcv(rcvpkt)) {
        if (is_file_info_pkt(rcvpkt)) {
            print_message("File name: " + string(rcvpkt.data), DEBUG);
            print_message("File size: " + to_string(rcvpkt.head.option), DEBUG);
            file_name = string(rcvpkt.data);
            file_size = rcvpkt.head.option;
            string file_path = get_file_path(file_name);
            print_message("File will be saved to " + file_path, DEBUG);
            print_message("Ready to receive files", SUC);
            packet sndpkt = make_pkt(ACK_FILE_INFO);
            udt_send(sndpkt);
            return true;
        } else if (isSYN(rcvpkt)) {
            //if the ack in handshake is lost, the sender will resend the SYN packet
            print_message("Received a SYN packet, reset the timer", WARNING);
            // wait for the file info again
            return ready_for_file(file_name, file_size);
        } else if (isFIN(rcvpkt)) {
            print_message("Received a FIN packet, close the connection", SUC);
            packet sndpkt = make_pkt(ACK_FIN);
            udt_send(sndpkt);
            return false;
        } else {
            print_message("Received a wrong packet", ERR);
            return false;
        }
    } else {
        print_message("Timeout when waiting for file info", ERR);
        return false;
    }
}

bool init_socket() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_message("WSAStartup failed!", ERR);
        return false;
    }
    socket_receiver = socket(AF_INET, SOCK_DGRAM, 0);
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(PORT);
    return true;
}

void init_IP() {
    addr_server.sin_addr.S_un.S_addr = inet_addr(LOCALHOST);
    addr_len = sizeof(addr_server);
}

void init_window_size() {
    print_message("Please input the window_size size, press ENTER to use default size: " + to_string(self_window_size), TIP);
    string input_window_size;
    getline(cin, input_window_size);
    if (!input_window_size.empty()) {
        self_window_size = stoi(input_window_size);
    }
    print_message("Receiver window_size size: " + to_string(self_window_size), DEBUG);
}

u_int get_seq_num(packet &packet1) {
    return packet1.head.seq;
}

int main() {
    assert(init_socket());
    //we assume the router is on the localhost
    init_IP();
    init_window_size();
    print_message("Receiver is running on localhost...", INFO);
    //set non-blocking socket
    ioctlsocket(socket_receiver, FIONBIO, &NON_BLOCK_IMODE);
    bind(socket_receiver, (SOCKADDR *) &addr_server, sizeof(addr_server));
    //handshake
    if (!handshake()) {
        print_message("Handshake failed, exit", ERR);
        return -1;
    }
    int received_file_num = 0;
    bool new_file_received = false;
    while (true) {
        char *file_buffer;
        packet rcvpkt;
        string file_name;
        u_int file_size;
        if (!ready_for_file(file_name, file_size)) {
            //end of the file transmission
            return 0;
        }
        file_buffer = new char[file_size];
        expectedseqnum = 0;
        int pkt_data_size;
        int received_file_len = 0;
        clock_t single_file_start = clock();
        //"blocking receive" here
        while (rdt_rcv(rcvpkt)) {
            if (not_corrupt(rcvpkt)) {
                if (hasseqnum(rcvpkt, expectedseqnum)) {
                    pkt_data_size = rcvpkt.head.data_size;
                    memcpy(file_buffer + received_file_len, rcvpkt.data, pkt_data_size);
                    received_file_len += pkt_data_size;
                    packet sndpkt = make_pkt(ACK,expectedseqnum);
                    udt_send(sndpkt);
                    print_message("Received packet " + to_string(expectedseqnum), DEBUG);
                    expectedseqnum++;
                } else {
                    //discard the packet and wait for the next one
                    print_message("Received out-of-order packet " + to_string(get_seq_num(rcvpkt)), DEBUG);
                    //send the ack of the last received packet
                    packet sndpkt = make_pkt(ACK,expectedseqnum - 1);
                    udt_send(sndpkt);
                    continue;
                }
            } else {
                print_message("Received a corrupt packet", DEBUG);
                continue;
            }
            if (received_file_len == file_size) {
                print_message("Received file successfully", SUC);
                print_message("Time used: " + to_string(clock() - single_file_start) + "ms", INFO);
                //write the file to disk
                string file_path = get_file_path(file_name);
                ofstream file(file_path, ios::binary);
                if (file.is_open()) {
                    file.write(file_buffer, file_size);
                    file.close();
                    print_message("File saved to " + file_path, SUC);
                    new_file_received = true;
                } else {
                    print_message("Failed to open file " + file_path, ERR);
                }
                break;
            }
        }
        if (!new_file_received) {
            //if the code reaches here, it means that sender unexpectedly closed when the file is not received completely
            print_message("Sender closed unexpectedly", ERR);
            return -1;
        } else {
            //reset the flag
            new_file_received = false;
            received_file_num++;
            print_message("Received " + to_string(received_file_num) + " files till now", TIP);
            //ready for the next file loop
        }
    }
}