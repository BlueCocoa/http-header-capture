//
//  main.cpp
//  http
//
//  Created by BlueCocoa on 16/5/21.
//  Copyright © 2016 BlueCocoa. All rights reserved.
//

#include <arpa/inet.h>
#include <ctype.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <regex>
#include <vector>
#include "xterm256.hpp"

using namespace std;

/**
 *  @brief  Regular expression for extracting HTTP Request
 */
regex http_request("([A-Z]+)( +)([^ ]+)( +)(HTTP)(/)(\\d+\\.\\d+)");

/**
 *  @brief  Regular expression for extracting HTTP Response
 */
regex http_response("(HTTP)(/)(\\d+\\.\\d+)( +)(\\d{3})( +)(.+)");

/**
 *  @brief  Regular expression for extracting HTTP Header Field
 */
regex http_header_field("(.*?)( *)(:)( *)(.+)");

/**
 *  @brief  xterm256 instance
 */
xterm256 xterm;

/**
 *  @brief  Highlight definitions
 */
xterm256::color function_c(0xa6, 0xe2, 0x2e);
xterm256::color text(0xf8, 0xf8, 0xf2);
xterm256::color ns(0xf8, 0xf8, 0xf2);
xterm256::color keyword(0x66, 0xd9, 0xef);
xterm256::color op(0xf9, 0x26, 0x72);
xterm256::color number(0xae, 0x81, 0xff);
xterm256::color reason(0xa6, 0xe2, 0x2e);
xterm256::color attribute(0xa6, 0xe2, 0x2e);
xterm256::color value(0xe6, 0xdb, 0x74);

/**
 *  @brief  Startswith
 *
 *  @param str    string
 *  @param prefix prefix
 *
 *  @return Return true if the given string starts with the prefix
 */
bool startswith(const char * str, const char * prefix) {
    bool result = false;
    size_t prefix_len = strlen(prefix);
    size_t str_len = strlen(str);
    
    if (str_len >= prefix_len) {
        result = true;
        for (size_t i = 0; i < prefix_len; i++) {
            if (str[i] != prefix[i]) {
                result = false;
                break;
            }
        }
    }
    
    return result;
}

/**
 *  @brief  First index of target string in the given source string
 *
 *  @param src    source string
 *  @param target target string
 *
 *  @return Returns a positive number to indicate the first index the target string occurs
 */
long long strpos(const char * src, const char * target) {
    size_t src_length = strlen(src);
    size_t target_length = strlen(target);
    int next[1024];
    size_t i = 0, j = 0;
    auto nexts = [&](){
        int j = 0, k = -1;
        next[0] = k;
        while (j < target_length - 1) {
            if (k == -1 || target[j] == target[k]) {
                j++;
                k++;
                next[j] = k;
            } else {
                k = next[k];
            }
        }
    };
    nexts();
    while (i < src_length) {
        if (j == -1 || src[i] == target[j]) {
            j++;
            i++;
        } else {
            j = next[j];
        }
        if (j == target_length) {
            return i - target_length;
        }
    }
    return -1;
}

/**
 *  @brief  Split the given string into lines
 *
 *  @param str string with "\r\n"
 *
 *  @return lines
 */
vector<string> splitlines(char * str) {
    vector<string> slines;
    
    for (int i = 0; i < strlen(str); i++) {
        int start = 0;
        char * string = str + i;
        
        for (; start < strlen(string); start++) {
            if (string[start] == '\r' && string[start + 1] == '\n') {
                break;
            }
        }
        string[start] = '\0';
        slines.emplace_back(string);
        string[start] = '\r';
        if (string[start + 2] == '\r' && string[start + 3] == '\n') {
            break;
        }
        i += start + 1;
    }
    
    return slines;
}

/**
 *  @brief  Parse the network packet we captured
 *
 *  @param packet Captured packet
 */
void parse_packet(const u_char * packet) {
    // Extract ether header from packet
    struct ether_header * ether = (struct ether_header *)packet;
    
    // IP Protocol number is 8
    int ether_protocol = ether->ether_type;
    if (ether_protocol == 8) {
        // Extract IP header from packet
        struct ip * ip = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Calculate size of IP header
        int ip_header_len = ip->ip_hl * 4;
        
        // TCP Protocol number is 6
        int ip_protocol = ip->ip_p;
        if (ip_protocol == 6) {
            // Extract TCP header from packet
            struct tcphdr * tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            
            // Calculate size of TCP header
            int tcp_header_len = tcp->th_off * 4;
            
            // TCP Port is 80
            int source_port = ntohs(tcp->th_sport);
            int dest_port = ntohs(tcp->th_dport);
            
            if (source_port == 80 or dest_port == 80) {
                // Sum header size of ether, IP and TCP
                int header_size = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                
                // Extract data from packet
                char * data = (char *)(packet + header_size);
                if (startswith(data, "HTTP")   or
                    startswith(data, "GET")    or
                    startswith(data, "POST")   or
                    startswith(data, "DELETE") or
                    startswith(data, "HEAD")   or
                    startswith(data, "PUT")    or
                    startswith(data, "TRACE")  or
                    startswith(data, "CONNECT")) {
                    
                    long long http_header_size = strpos(data, "\r\n\r\n");
                    if (http_header_size > 0) {
                        cout << "Source: " << inet_ntoa(ip->ip_src) << ":" << source_port << '\n';
                        cout << "Destination: " << inet_ntoa(ip->ip_dst) << ":" << dest_port << '\n';
                        
                        data[http_header_size] = '\0';
                        
                        vector<string> header_data = splitlines(data);
                        bool flag = true;
                        
                        for (int i = 0; i < header_data.size(); i++) {
                            smatch matches;
                            string & line = header_data[i];
                            if (flag && regex_match(line, matches, http_request)) {
                                flag = false;
                                xterm   << function_c   << matches[1].str()
                                        << text         << matches[2].str()
                                        << ns           << matches[3].str()
                                        << text         << matches[4].str()
                                        << keyword      << matches[5].str()
                                        << op           << matches[6].str()
                                        << number       << matches[7].str()
                                        << '\n';
                            } else if (flag && regex_match(line, matches, http_response)) {
                                flag = false;
                                xterm   << keyword      << matches[1].str()
                                        << op           << matches[2].str()
                                        << number       << matches[3].str()
                                        << text         << matches[4].str()
                                        << number       << matches[5].str()
                                        << text         << matches[6].str()
                                        << reason       << matches[7].str()
                                        << '\n';
                            } else if (regex_match(line, matches, http_header_field)) {
                                xterm   << attribute    << matches[1].str()
                                        << text         << matches[2].str()
                                        << op           << matches[3].str()
                                        << text         << matches[4].str()
                                        << value        << matches[5].str()
                                        << '\n';
                            } else {
                                xterm << line << '\n';
                            }
                            xterm << "\e[0m";
                            std::cout<<std::flush;
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, const char * argv[]) {
    pcap_if_t * devices;
    pcap_if_t * iterator;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        perror("pcap_findalldevs");
        exit(-1);
    }
    
    printf("Avaiable devices:\n");
    for (iterator = devices; iterator != NULL; iterator = iterator->next) {
        cout << iterator->name << '\n';
    }
    
    string device;
    cout << "Choose a device to sniff: ";
    cin >> device;
    
    bool found = false;
    for (iterator = devices; iterator != NULL; iterator = iterator->next) {
        if (strcmp(iterator->name, device.c_str()) == 0) {
            found = true;
            break;
        }
    }
    
    if (!found) {
        cout << "No such device!\n";
        exit(-1);
    }
    
    pcap_t * pcap_fd = pcap_open_live(device.c_str(), 65536, 1, 0, errbuf);
    if (!pcap_fd) {
        cout << errbuf << '\n';
        exit(-1);
    }
    
    struct pcap_pkthdr header;
    const u_char * packet;
    while (1) {
        packet = pcap_next(pcap_fd, &header);
        const u_char * copy = (const u_char *)malloc(header.caplen + 1);
        memset((void *)copy, 0, header.caplen + 1);
        memcpy((void *)copy, packet, header.caplen);
        parse_packet(copy);
        free((void *)copy);
    }
}
