#include <windows.h>
#include <iostream>
#include <cstdio>

#ifndef DEFINITION_H
#define DEFINITION_H
#endif //DEFINITION_H
using namespace std;
u_long NON_BLOCK_IMODE = 1;
u_long BLOCK_IMODE = 0;
#define LOCALHOST "127.0.0.1"
#define BUFFER_SIZE 10000000

#define MAX_RESEND_TIMES 10
#define MAX_WRONG_TIMES 10
const int MAX_TIME = CLOCKS_PER_SEC;
const int MAX_FILE_WAIT_TIME =60*CLOCKS_PER_SEC;
#define MAX_SIZE 1024
#define DATA 0x0
#define FIN 0x1
#define SYN 0x2
#define ACK 0x4
#define ACK_SYN 0x6
#define ACK_FIN 0x5
#define FILE_HEAD 0x8
// datagram format:
#pragma pack(1)
struct packet_head {
    u_int seq;
    u_short check_sum;
    u_short data_size;
    u_short flag;
    u_short window_size;
    u_int option;

    packet_head() {
        seq = 0;
        check_sum = 0;
        data_size = 0;
        flag = 0;
        window_size = 0;
        option = 0;
    }
};

struct packet {
    packet_head head;
    char data[MAX_SIZE]{};

    packet() {
        packet_head();
        memset(data, 0, MAX_SIZE);
    }
};

#pragma pack()

const int HEAD_SIZE = sizeof(packet_head);
const int PACKET_SIZE = sizeof(packet);
#define SEND0 0
#define SEND1 1
#define WAIT0 0
#define WAIT1 1

//useful functions
u_short check_sum(u_short *packet, int packet_len) {
    u_long sum = 0;
    // make 16 bit words adjacent
    int count = (packet_len + 1) / 2;
    auto *temp = new u_short[count + 1];
    memset(temp, 0, count + 1);
    memcpy(temp, packet, packet_len);
    while (count--) {
        sum += *temp++;
        //overflow carry
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    //complement
    return ~(sum & 0xFFFF);
}

bool not_corrupt(packet &p) {
    return check_sum((u_short *) &p, HEAD_SIZE + p.head.data_size) == 0;
}

bool corrupt(packet &p) {
    return check_sum((u_short *) &p, HEAD_SIZE + p.head.data_size) != 0;
}

packet make_pkt(u_int flag, u_int seq = 0, u_short data_size = 0, const char *data = nullptr, u_short window_size = 0,
                u_int option = 0) {
    packet pkt;
    pkt.head.flag = flag;
    pkt.head.seq = seq;
    pkt.head.window_size = window_size;
    pkt.head.data_size = data_size;
    pkt.head.option = option;
    if (data != nullptr) {
        memcpy(pkt.data, data, data_size);
    }
    pkt.head.check_sum = check_sum((u_short *) &pkt, PACKET_SIZE);
    return pkt;
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
bool isFIN(packet &packet1) {
    return (packet1.head.flag & FIN);
}
bool timeout(int start_time) {
    return clock() - start_time > MAX_TIME;
}

bool wait_file_timeout(int start_time) {
    return clock() - start_time > MAX_FILE_WAIT_TIME;
}

void color_print(const char *s, int color) {
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    printf(s);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}

// string version
void color_print(const std::string &s, int color) {
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    cout << s;
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}

// message colors
#define ERR 4
#define INFO 7
#define SUC 10
#define TIP 1
#define DEBUG 8
#define WARNING 6

//print message
void print_message(const string &msg, int type) {
    switch (type) {
        case ERR:
            color_print("[ERROR] ", ERR);
            break;
        case INFO:
            color_print("[INFO] ", INFO);
            break;
        case SUC:
            color_print("[SUCCESS] ", SUC);
            break;
        case TIP:
            color_print("[TIP] ", TIP);
            break;
        case DEBUG:
            color_print("[DEBUG] ", DEBUG);
            break;
        case WARNING:
            color_print("[WARNING] ", WARNING);
        default:
            break;
    }
    color_print(msg, INFO);
    cout << endl;
}

void print_message(const char *msg, int type) {
    switch (type) {
        case ERR:
            color_print("[ERROR] ", ERR);
            break;
        case INFO:
            color_print("[INFO] ", INFO);
            break;
        case SUC:
            color_print("[SUCCESS] ", SUC);
            break;
        case TIP:
            color_print("[TIP] ", TIP);
            break;
        case DEBUG:
            color_print("[DEBUG] ", DEBUG);
            break;
        case WARNING:
            color_print("[WARNING] ", WARNING);
        default:
            break;
    }
    color_print(msg, INFO);
    cout << endl;
}