#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <omp.h>
#include <math.h>

#define MAX_FILENAME 256
#define MAX_FLOWS 1000000
#define THREAD_COUNT 8

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_features {
    struct flow_key key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t start_time;
    uint64_t last_time;
    uint32_t fwd_packet_count;
    uint32_t bwd_packet_count;
    uint64_t fwd_byte_count;
    uint64_t bwd_byte_count;
    uint32_t fwd_packet_length_min;
    uint32_t fwd_packet_length_max;
    double fwd_packet_length_mean;
    double fwd_packet_length_std;
    uint32_t bwd_packet_length_min;
    uint32_t bwd_packet_length_max;
    double bwd_packet_length_mean;
    double bwd_packet_length_std;
    double flow_bytes_per_sec;
    double flow_packets_per_sec;
    double flow_iat_mean;
    double flow_iat_std;
    double flow_iat_max;
    double flow_iat_min;
    uint32_t fwd_psh_flags;
    uint32_t bwd_psh_flags;
    uint32_t fwd_urg_flags;
    uint32_t bwd_urg_flags;
    uint64_t fwd_header_length;
    uint64_t bwd_header_length;
    uint32_t fin_flag_count;
    uint32_t syn_flag_count;
    uint32_t rst_flag_count;
    uint32_t psh_flag_count;
    uint32_t ack_flag_count;
    uint32_t urg_flag_count;
    double down_up_ratio;
    double avg_packet_size;
    double avg_fwd_segment_size;
    double avg_bwd_segment_size;
    uint32_t subflow_fwd_packets;
    uint32_t subflow_fwd_bytes;
    uint32_t subflow_bwd_packets;
    uint32_t subflow_bwd_bytes;
    uint32_t init_win_bytes_forward;
    uint32_t init_win_bytes_backward;
    uint32_t active_mean;
    uint32_t idle_mean;
};

struct thread_data {
    pcap_t *handle;
    FILE *output_file;
    pthread_mutex_t *file_mutex;
};

void process_packet(const struct pcap_pkthdr *header, const u_char *packet, struct flow_features *flows, int *flow_count) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet
    struct flow_key key;
    int i;

    key.src_ip = ip_header->ip_src.s_addr;
    key.dst_ip = ip_header->ip_dst.s_addr;
    key.protocol = ip_header->ip_p;

    if (key.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
        key.src_port = ntohs(tcp_header->th_sport);
        key.dst_port = ntohs(tcp_header->th_dport);
    } else if (key.protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
        key.src_port = ntohs(udp_header->uh_sport);
        key.dst_port = ntohs(udp_header->uh_dport);
    } else {
        key.src_port = 0;
        key.dst_port = 0;
    }

    #pragma omp critical
    {
        for (i = 0; i < *flow_count; i++) {
            if (memcmp(&flows[i].key, &key, sizeof(struct flow_key)) == 0) {
                break;
            }
        }

        if (i == *flow_count) {
            if (*flow_count < MAX_FLOWS) {
                flows[i].key = key;
                flows[i].packet_count = 0;
                flows[i].byte_count = 0;
                flows[i].start_time = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
                flows[i].fwd_packet_count = 0;
                flows[i].bwd_packet_count = 0;
                flows[i].fwd_byte_count = 0;
                flows[i].bwd_byte_count = 0;
                flows[i].fwd_packet_length_min = UINT32_MAX;
                flows[i].fwd_packet_length_max = 0;
                flows[i].fwd_packet_length_mean = 0;
                flows[i].fwd_packet_length_std = 0;
                flows[i].bwd_packet_length_min = UINT32_MAX;
                flows[i].bwd_packet_length_max = 0;
                flows[i].bwd_packet_length_mean = 0;
                flows[i].bwd_packet_length_std = 0;
                flows[i].flow_bytes_per_sec = 0;
                flows[i].flow_packets_per_sec = 0;
                flows[i].flow_iat_mean = 0;
                flows[i].flow_iat_std = 0;
                flows[i].flow_iat_max = 0;
                flows[i].flow_iat_min = UINT64_MAX;
                flows[i].fwd_psh_flags = 0;
                flows[i].bwd_psh_flags = 0;
                flows[i].fwd_urg_flags = 0;
                flows[i].bwd_urg_flags = 0;
                flows[i].fwd_header_length = 0;
                flows[i].bwd_header_length = 0;
                flows[i].fin_flag_count = 0;
                flows[i].syn_flag_count = 0;
                flows[i].rst_flag_count = 0;
                flows[i].psh_flag_count = 0;
                flows[i].ack_flag_count = 0;
                flows[i].urg_flag_count = 0;
                flows[i].down_up_ratio = 0;
                flows[i].avg_packet_size = 0;
                flows[i].avg_fwd_segment_size = 0;
                flows[i].avg_bwd_segment_size = 0;
                flows[i].subflow_fwd_packets = 0;
                flows[i].subflow_fwd_bytes = 0;
                flows[i].subflow_bwd_packets = 0;
                flows[i].subflow_bwd_bytes = 0;
                flows[i].init_win_bytes_forward = 0;
                flows[i].init_win_bytes_backward = 0;
                flows[i].active_mean = 0;
                flows[i].idle_mean = 0;
                (*flow_count)++;
            } else {
                return; // Skip if max flows reached
            }
        }

        flows[i].packet_count++;
        flows[i].byte_count += header->len;
        uint64_t current_time = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
        
        if (flows[i].packet_count > 1) {
            uint64_t iat = current_time - flows[i].last_time;
            flows[i].flow_iat_mean = (flows[i].flow_iat_mean * (flows[i].packet_count - 2) + iat) / (flows[i].packet_count - 1);
            flows[i].flow_iat_std = sqrt((flows[i].flow_iat_std * flows[i].flow_iat_std * (flows[i].packet_count - 2) +
                                         (iat - flows[i].flow_iat_mean) * (iat - flows[i].flow_iat_mean)) / (flows[i].packet_count - 1));
            flows[i].flow_iat_max = (iat > flows[i].flow_iat_max) ? iat : flows[i].flow_iat_max;
            flows[i].flow_iat_min = (iat < flows[i].flow_iat_min) ? iat : flows[i].flow_iat_min;
        }
        
        flows[i].last_time = current_time;

        // Update forward/backward packet counts and byte counts
        if (key.src_ip < key.dst_ip || (key.src_ip == key.dst_ip && key.src_port < key.dst_port)) {
            flows[i].fwd_packet_count++;
            flows[i].fwd_byte_count += header->len;
            if (header->len < flows[i].fwd_packet_length_min) flows[i].fwd_packet_length_min = header->len;
            if (header->len > flows[i].fwd_packet_length_max) flows[i].fwd_packet_length_max = header->len;
            flows[i].fwd_packet_length_mean = (flows[i].fwd_packet_length_mean * (flows[i].fwd_packet_count - 1) + header->len) / flows[i].fwd_packet_count;
        } else {
            flows[i].bwd_packet_count++;
            flows[i].bwd_byte_count += header->len;
            if (header->len < flows[i].bwd_packet_length_min) flows[i].bwd_packet_length_min = header->len;
            if (header->len > flows[i].bwd_packet_length_max) flows[i].bwd_packet_length_max = header->len;
            flows[i].bwd_packet_length_mean = (flows[i].bwd_packet_length_mean * (flows[i].bwd_packet_count - 1) + header->len) / flows[i].bwd_packet_count;
        }

        if (key.protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
            flows[i].fin_flag_count += (tcp_header->th_flags & TH_FIN) ? 1 : 0;
            flows[i].syn_flag_count += (tcp_header->th_flags & TH_SYN) ? 1 : 0;
            flows[i].rst_flag_count += (tcp_header->th_flags & TH_RST) ? 1 : 0;
            flows[i].psh_flag_count += (tcp_header->th_flags & TH_PUSH) ? 1 : 0;
            flows[i].ack_flag_count += (tcp_header->th_flags & TH_ACK) ? 1 : 0;
            flows[i].urg_flag_count += (tcp_header->th_flags & TH_URG) ? 1 : 0;
        }

        // Calculate other features
        flows[i].flow_bytes_per_sec = flows[i].byte_count / ((current_time - flows[i].start_time) / 1000000.0);
        flows[i].flow_packets_per_sec = flows[i].packet_count / ((current_time - flows[i].start_time) / 1000000.0);
        flows[i].down_up_ratio = (double)flows[i].bwd_byte_count / (flows[i].fwd_byte_count + 1);
        flows[i].avg_packet_size = (double)flows[i].byte_count / flows[i].packet_count;
        flows[i].avg_fwd_segment_size = (double)flows[i].fwd_byte_count / (flows[i].fwd_packet_count + 1);
        flows[i].avg_bwd_segment_size = (double)flows[i].bwd_byte_count / (flows[i].bwd_packet_count + 1);
    }
}

void *process_pcap(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct flow_features flows[MAX_FLOWS];
    int flow_count = 0;

    while ((packet = pcap_next(data->handle, &header)) != NULL) {
        process_packet(&header, packet, flows, &flow_count);
    }

    pthread_mutex_lock(data->file_mutex);
    for (int i = 0; i < flow_count; i++) {
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = flows[i].key.src_ip;
        dst_ip.s_addr = flows[i].key.dst_ip;
        fprintf(data->output_file, "%s,%s,%u,%u,%u,%lu,%lu,%lu,%lu,%u,%u,%u,%u,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%lu,%lu,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                inet_ntoa(src_ip), inet_ntoa(dst_ip), ntohs(flows[i].key.src_port), ntohs(flows[i].key.dst_port),
                flows[i].key.protocol, flows[i].packet_count, flows[i].byte_count, flows[i].fwd_packet_count, flows[i].bwd_packet_count,
                flows[i].fwd_packet_length_min, flows[i].fwd_packet_length_max, flows[i].bwd_packet_length_min, flows[i].bwd_packet_length_max,
                flows[i].fwd_packet_length_mean, flows[i].bwd_packet_length_mean, flows[i].fwd_psh_flags, flows[i].bwd_psh_flags,
                flows[i].flow_bytes_per_sec, flows[i].flow_packets_per_sec, flows[i].flow_iat_mean, flows[i].flow_iat_std,
                flows[i].flow_iat_max, flows[i].flow_iat_min, flows[i].fwd_packet_length_std, flows[i].bwd_packet_length_std,
                flows[i].avg_fwd_segment_size, flows[i].avg_bwd_segment_size, flows[i].subflow_fwd_packets, flows[i].subflow_bwd_packets
                flows[i].subflow_fwd_bytes, flows[i].subflow_bwd_bytes, flows[i].init_win_bytes_forward, flows[i].init_win_bytes_backward,
                flows[i].active_mean, flows[i].idle_mean);
    }
    pthread_mutex_unlock(data->file_mutex);
}

void pcap_to_csv(const char *pcap_file, const char *csv_file) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE *output_file;
    pthread_t threads[THREAD_COUNT];
    struct thread_data thread_data[THREAD_COUNT];
    pthread_mutex_t file_mutex;

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    output_file = fopen(csv_file, "w");
    if (output_file == NULL) {
        fprintf(stderr, "Error opening output file\n");
        pcap_close(handle);
        return;
    }

    pthread_mutex_init(&file_mutex, NULL);

    // Write CSV header
    fprintf(output_file, "Source IP,Destination IP,Source Port,Destination Port,Protocol,Packet Count,Byte Count,Forward Packet Count,Backward Packet Count,Forward Packet Length Min,Forward Packet Length Max,Backward Packet Length Min,Backward Packet Length Max,Forward Packet Length Mean,Backward Packet Length Mean,Forward PSH Flags,Backward PSH Flags,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Forward Packet Length Std,Backward Packet Length Std,Average Forward Segment Size,Average Backward Segment Size,Subflow Forward Packets,Subflow Backward Packets,Subflow Forward Bytes,Subflow Backward Bytes,Init Win Bytes Forward,Init Win Bytes Backward,Active Mean,Idle Mean\n");

    for (int i = 0; i < THREAD_COUNT; i++) {
        thread_data[i].handle = pcap_open_offline(pcap_file, errbuf);
        thread_data[i].output_file = output_file;
        thread_data[i].file_mutex = &file_mutex;
        pthread_create(&threads[i], NULL, process_pcap_chunk, &thread_data[i]);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        pcap_close(thread_data[i].handle);
    }

    pthread_mutex_destroy(&file_mutex);
    fclose(output_file);
    pcap_close(handle);
}

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <omp.h>
#include <math.h>

// ... (include all the necessary struct definitions from the previous code)

void *process_pcap_chunk(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct flow_features flows[MAX_FLOWS];
    int flow_count = 0;

    while ((packet = pcap_next(data->handle, &header)) != NULL) {
        process_packet(&header, packet, flows, &flow_count);
    }

    pthread_mutex_lock(data->file_mutex);
    for (int i = 0; i < flow_count; i++) {
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = flows[i].key.src_ip;
        dst_ip.s_addr = flows[i].key.dst_ip;
        fprintf(data->output_file, "%s,%s,%u,%u,%u,%lu,%lu,%lu,%lu,%u,%u,%u,%u,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%lu,%lu,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
        inet_ntoa(src_ip), inet_ntoa(dst_ip), ntohs(flows[i].key.src_port), ntohs(flows[i].key.dst_port),
        flows[i].key.protocol, flows[i].packet_count, flows[i].byte_count, flows[i].fwd_packet_count, flows[i].bwd_packet_count,
        flows[i].fwd_packet_length_min, flows[i].fwd_packet_length_max, flows[i].bwd_packet_length_min, flows[i].bwd_packet_length_max,
        flows[i].fwd_packet_length_mean, flows[i].bwd_packet_length_mean, flows[i].fwd_psh_flags, flows[i].bwd_psh_flags,
        flows[i].flow_bytes_per_sec, flows[i].flow_packets_per_sec, flows[i].flow_iat_mean, flows[i].flow_iat_std,
        flows[i].flow_iat_max, flows[i].flow_iat_min, flows[i].fwd_packet_length_std, flows[i].bwd_packet_length_std,
        flows[i].avg_fwd_segment_size, flows[i].avg_bwd_segment_size, flows[i].subflow_fwd_packets, flows[i].subflow_bwd_packets,
        flows[i].subflow_fwd_bytes, flows[i].subflow_bwd_bytes, flows[i].init_win_bytes_forward, flows[i].init_win_bytes_backward,
        flows[i].active_mean, flows[i].idle_mean,
        flows[i].fwd_urg_flags, flows[i].bwd_urg_flags, flows[i].fwd_header_length, flows[i].bwd_header_length,
        flows[i].fin_flag_count, flows[i].syn_flag_count, flows[i].rst_flag_count, flows[i].psh_flag_count,
        flows[i].ack_flag_count, flows[i].urg_flag_count);
}
pthread_mutex_unlock(data->file_mutex);

    return NULL;
}

void pcap_to_csv(const char *pcap_file, const char *csv_file) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE *output_file;
    pthread_t threads[THREAD_COUNT];
    struct thread_data thread_data[THREAD_COUNT];
    pthread_mutex_t file_mutex;

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    output_file = fopen(csv_file, "w");
    if (output_file == NULL) {
        fprintf(stderr, "Error opening output file\n");
        pcap_close(handle);
        return;
    }

    pthread_mutex_init(&file_mutex, NULL);

    // Write CSV header
    fprintf(output_file, "Source IP,Destination IP,Source Port,Destination Port,Protocol,Packet Count,Byte Count,Forward Packet Count,Backward Packet Count,Forward Packet Length Min,Forward Packet Length Max,Backward Packet Length Min,Backward Packet Length Max,Forward Packet Length Mean,Backward Packet Length Mean,Forward PSH Flags,Backward PSH Flags,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Forward Packet Length Std,Backward Packet Length Std,Average Forward Segment Size,Average Backward Segment Size,Subflow Forward Packets,Subflow Backward Packets,Subflow Forward Bytes,Subflow Backward Bytes,Init Win Bytes Forward,Init Win Bytes Backward,Active Mean,Idle Mean\n");

    for (int i = 0; i < THREAD_COUNT; i++) {
        thread_data[i].handle = pcap_open_offline(pcap_file, errbuf);
        thread_data[i].output_file = output_file;
        thread_data[i].file_mutex = &file_mutex;
        pthread_create(&threads[i], NULL, process_pcap_chunk, &thread_data[i]);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        pcap_close(thread_data[i].handle);
    }

    pthread_mutex_destroy(&file_mutex);
    fclose(output_file);
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_pcap> <output_csv>\n", argv[0]);
        return 1;
    }

    pcap_to_csv(argv[1], argv[2]);
    return 0;
}