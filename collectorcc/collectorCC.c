#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _CUSTOM_DIAG_HEADER__
#include "tcp.h"
#include "sock_diag.h"
#include "inet_diag.h"
#else
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/netlink.h>
#include <libmnl/libmnl.h>

#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <getopt.h>

struct diag_handle {
    struct mnl_socket *mnl;
    struct nlmsghdr *nlh;
};

struct inaddr_prefix {
    int af;
    uint16_t bytelen;
    uint16_t bitlen;
    uint32_t mask[4];
    uint32_t addr[4];
};

struct diag_sockinfo {
    unsigned int type;
    uint16_t prot;
    struct inaddr_prefix local;
    struct inaddr_prefix remote;
    uint16_t local_port;
    uint16_t remote_port;
    int state;
    char cong_name[16];
    unsigned int uid;
    unsigned int iface;
    struct tcp_info *tp;
    int has_cong_name;
#ifdef GET_BBRX_INFO
    struct tcp_bbrx_info *bbrx_info;
#endif
    struct tcp_bbr_info *bbr_info;
};

// Global variables
#define BUFSIZE 8192
static char buf[BUFSIZE];

struct diag_handle *h;

#define TRUE 1
#define FALSE 0

FILE *output_file;
int one_object_array;
int pulling;
int first;

void init_global_variables()
{
    // Initializing global variable
    output_file = stdout;
    one_object_array = TRUE;
    pulling = FALSE;
    first = TRUE;
}

/* from include/net/tcp_states.h */
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,	/* Now a valid state */
    TCP_NEW_SYN_RECV,

    TCP_MAX_STATES	/* Leave at the end! */
};

static const char* tcp_states_map[] = {
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT]    = "SYN-SENT",
    [TCP_SYN_RECV]    = "SYN-RECV",
    [TCP_FIN_WAIT1]   = "FIN-WAIT-1",
    [TCP_FIN_WAIT2]   = "FIN-WAIT-2",
    [TCP_TIME_WAIT]   = "TIME-WAIT",
    [TCP_CLOSE]       = "CLOSE",
    [TCP_CLOSE_WAIT]  = "CLOSE-WAIT",
    [TCP_LAST_ACK]    = "LAST-ACK",
    [TCP_LISTEN]      = "LISTEN",
    [TCP_CLOSING]     = "CLOSING"
};

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

#if 0
// Currently unused
// util -> bw calculation
static char *sprint_bw(char *buf, double bw)
{
    if (bw > 1000000.0)
        sprintf(buf, "%.1fM", bw / 1000000.0);
    else if (bw > 1000.0)
        sprintf(buf, "%.1fK", bw / 1000.0);
    else
        sprintf(buf, "%g", bw);

    return buf;
}
#endif

static struct diag_handle *diag_open_socket()
{
    struct mnl_socket *nl;
    struct diag_handle *handle = malloc(sizeof *handle);

    if (!handle)
        return NULL;

    nl = mnl_socket_open(NETLINK_INET_DIAG);
    if (nl == NULL) {
        fprintf(stderr, "failed to create socket\n");
        free(handle);
        return NULL;
    }

    handle->mnl = nl;

    return handle;
}

static void diag_close_socket(struct diag_handle *handle)
{
    struct mnl_socket *nl = handle->mnl;
    mnl_socket_close(nl);
    free(handle);
}

static int diag_subscribe(struct diag_handle *h, unsigned int group)
{
    /*
    int fd = mnl_socket_get_fd(h->mnl);
    return setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
    */

    if (mnl_socket_bind(h->mnl, group, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }

    return 0;
}

static int diag_build_msg(struct diag_handle *h, char *buf, unsigned short int family)
{
#if 1
    struct inet_diag_req_v2 *req = NULL;
    typedef struct inet_diag_req_v2 inet_diag_req_t;
#else
    struct inet_diag_req *req = NULL;
    typedef struct inet_diag_req inet_diag_req_t;
#endif
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);

    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    //nlh->nlmsg_len = NLMSG_LENGTH(sizeof *req);

    req = mnl_nlmsg_put_extra_header(nlh, sizeof(inet_diag_req_t));

    req->sdiag_protocol = IPPROTO_TCP;
	req->sdiag_family = family;
    req->idiag_states = TCPF_ALL & 
        ~((1 << TCP_SYN_RECV) | (1 << TCP_TIME_WAIT) | (1 << TCP_CLOSE));
    /* get protocol info */
    req->idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    /* request congestion control type */
    req->idiag_ext |= (1 << (INET_DIAG_CONG - 1));
    // In my understanding, we need to use inet_diag_req_v2 structure if we want
    // to use the following flags
#ifdef GET_BBRX_INFO
    /* request bbrx info */
    req->idiag_ext |= (1 << (INET_DIAG_BBRXINFO - 1));
#endif
    req->idiag_ext |= (1 << (INET_DIAG_BBRINFO - 1));
    //req->idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));

    h->nlh = nlh;

    return 0;
}

static int diag_send_msg(struct diag_handle *h)
{
    struct mnl_socket *nl = h->mnl;
    struct nlmsghdr *nlh = h->nlh;
    ssize_t sent = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);

    return sent;
}

static int diag_data_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, INET_DIAG_MAX) < 0)
        return MNL_CB_OK;
    tb[type] = attr;

    return MNL_CB_OK;
}

static void diag_dump_sockinfo(struct diag_sockinfo *info)
{
    char buf_src[INET6_ADDRSTRLEN] = { 0 };
    char buf_dst[INET6_ADDRSTRLEN] = { 0 };
    struct passwd *uid_info = NULL;

    if (info->tp) {
        if (one_object_array && first) {
            first = FALSE;
        } else {
            fprintf(output_file, ",\n");
        }

        uid_info = getpwuid(info->uid);
        fprintf(output_file,
                "{"
                    "\"user\":\"%s\","
                    "\"uid\":%u,"
                    "\"srcip\":\"%s\","
                    "\"srcport\":%d,"
                    "\"dstip\":\"%s\","
                    "\"dstport\": %d", 
             uid_info == NULL ? "Not found" : uid_info->pw_name,
             info->uid,
             inet_ntop(info->local.af, info->local.addr, buf_src, INET6_ADDRSTRLEN),
             ntohs(info->local_port),
             inet_ntop(info->remote.af, info->remote.addr, buf_dst, INET6_ADDRSTRLEN),
             ntohs(info->remote_port)
        );

        fprintf(output_file,
                    ","
                    "\"state\":\"%s\","
                    "\"flow_stats\":{"
                        "\"rtt\":%g,"
                        "\"rtt_var\":%g,"
                        "\"rcv_rtt\":%g,"
                        "\"ato\":%g,"
                        "\"snd_mss\":%d,"
                        "\"unacked\":%u,"
                        "\"retrans\":%u,"
                        "\"lost\":%u,"
                        "\"snd_cwnd\":%u,"
                        "\"castate\":\"%u\","
                        "\"retransmits\":\"%u\","
                        "\"probes\":\"%u\","
                        "\"backoff\":\"%u\","
                        "\"options\":\"%u\","
                        "\"sndwscale\":\"%u\","
                        "\"rcvwscale\":\"%u\","
                        "\"delivery_rate_app_limited\":\"%u\","
                        "\"rto\":\"%u\","
                        "\"rcvmss\":\"%u\","
                        "\"sacked\":\"%u\","
                        "\"fackets\":\"%u\","
                        "\"lastdatasent\":\"%u\","
                        "\"lastacksent\":\"%u\","
                        "\"lastdatarecv\":\"%u\","
                        "\"lastackrecv\":\"%u\","
                        "\"pmtu\":\"%u\","
                        "\"rcvssthresh\":\"%u\","
                        "\"sndssthresh\":\"%u\","
                        "\"advmss\":\"%u\","
                        "\"reordering\":\"%u\","
                        "\"rcvspace\":\"%u\","
                        "\"totalretrans\":\"%u\","
                        "\"pacing_rate\":\"%llu\","
                        "\"max_pacing_rate\":\"%llu\","
                        "\"bytes_acked\":\"%llu\","
                        "\"bytes_received\":\"%llu\","
                        "\"segs_out\":\"%u\","
                        "\"segs_in\":\"%u\","
                        "\"notsent_bytes\":\"%u\","
                        "\"min_rtt\":\"%u\","
                        "\"data_segs_in\":\"%u\","
                        "\"data_segs_out\":\"%u\","
                        "\"delivery_rate\":\"%llu\","
                        "\"busy_time\":\"%llu\","
                        "\"rwnd_limited\":\"%llu\","
                        "\"sndbuf_limited\":\"%llu\"",
            tcp_states_map[info->tp->tcpi_state],
            (double) info->tp->tcpi_rtt/1000,
            (double) info->tp->tcpi_rttvar/1000,
            (double) info->tp->tcpi_rcv_rtt/1000,
            (double) info->tp->tcpi_ato/1000,
            info->tp->tcpi_snd_mss,
            info->tp->tcpi_unacked,
            info->tp->tcpi_retrans,
            info->tp->tcpi_lost,
            info->tp->tcpi_snd_cwnd,
            info->tp->tcpi_ca_state,
            info->tp->tcpi_retransmits,
            info->tp->tcpi_probes,
            info->tp->tcpi_backoff,
            info->tp->tcpi_options,
            info->tp->tcpi_snd_wscale,
            info->tp->tcpi_rcv_wscale,
            info->tp->tcpi_delivery_rate_app_limited,
            info->tp->tcpi_rto,
            info->tp->tcpi_rcv_mss,
            info->tp->tcpi_sacked,
            info->tp->tcpi_fackets,
            info->tp->tcpi_last_data_sent,
            info->tp->tcpi_last_ack_sent,
            info->tp->tcpi_last_data_recv,
            info->tp->tcpi_last_ack_recv,
            info->tp->tcpi_pmtu,
            info->tp->tcpi_rcv_ssthresh,
            info->tp->tcpi_snd_ssthresh,
            info->tp->tcpi_advmss,
            info->tp->tcpi_reordering,
            info->tp->tcpi_rcv_space,
            info->tp->tcpi_total_retrans,
            info->tp->tcpi_pacing_rate,
            info->tp->tcpi_max_pacing_rate,
            info->tp->tcpi_bytes_acked,
            info->tp->tcpi_bytes_received,
            info->tp->tcpi_segs_out,
            info->tp->tcpi_segs_in,
            info->tp->tcpi_notsent_bytes,
            info->tp->tcpi_min_rtt,
            info->tp->tcpi_data_segs_in,
            info->tp->tcpi_data_segs_out,
            info->tp->tcpi_delivery_rate,
            info->tp->tcpi_busy_time,
            info->tp->tcpi_rwnd_limited,
            info->tp->tcpi_sndbuf_limited
        );

        if (info->has_cong_name) {
            fprintf(output_file,
                        ","
                        "\"congalg\":\"%s\"",
                info->cong_name
            );
        }

#ifdef GET_BBRX_INFO
        if (info->bbrx_info && strstr(info->cong_name, "bbrx") != NULL) {
            fprintf(output_file,
                        ","
                        "\"cong_control\":{"
                            "\"bbrx\":{"
                                "\"bbrx_bw_lo\":%u,"
                                "\"bbrx_bw_hi\":%u,"
                                "\"bbrx_min_rtt\":%u,"
                                "\"bbrx_brst_len\":%u,"
                                "\"bbrx_brst_tput\":%u,"
                                "\"bbrx_brst_ploss\":%u,"
                                "\"bbrx_brst_k\":%u,"
                                "\"bbrx_brst_beta\":%u"
                            "}"
                        "}",
                info->bbrx_info->bbrx_bw_lo,
                info->bbrx_info->bbrx_bw_hi,
                info->bbrx_info->bbrx_min_rtt,
                info->bbrx_info->bbrx_brst_len,
                info->bbrx_info->bbrx_brst_tput,
                info->bbrx_info->bbrx_brst_ploss,
                info->bbrx_info->bbrx_brst_k,
                info->bbrx_info->bbrx_brst_beta
            );
        }
#endif

        if (info->bbr_info && strstr(info->cong_name, "bbr") != NULL) {
            fprintf(output_file,
                        ","
                        "\"cong_control\":{"
                            "\"bbr\":{"
                                "\"bbr_bw_lo\":%u,"
                                "\"bbr_bw_hi\":%u,"
                                "\"bbr_min_rtt\":%u,"
                                "\"bbr_pacing_gain\":%u,"
                                "\"bbr_cwnd_gain\":%u"
                            "}"
                        "}",
                info->bbr_info->bbr_bw_lo,
                info->bbr_info->bbr_bw_hi,
                info->bbr_info->bbr_min_rtt,
                info->bbr_info->bbr_pacing_gain,
                info->bbr_info->bbr_cwnd_gain
            );
        }

        fprintf(output_file,
                    "}"
                "}\n"
        );
    } 
}

/**
 * Check if the connection is from/to the localhost
 *
 * Return:
 *     >  0: The connection is from/to the localhost
 *     == 0: The connection is not from/to the localhost
 *     <  0: Error occured
 */
static int is_localhost(struct inet_diag_msg *idm)
{
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];

    if (!idm) {
        return MNL_CB_ERROR;
    }

    if (idm->idiag_family == AF_INET) {
        inet_ntop(AF_INET, (struct in_addr*) &(idm->id.idiag_src), 
                local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(idm->id.idiag_dst), 
                remote_addr_buf, INET_ADDRSTRLEN);
    } else if (idm->idiag_family == AF_INET6) {
        inet_ntop(AF_INET6, (struct in_addr6*) &(idm->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(idm->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return MNL_CB_ERROR;
    }

    if (local_addr_buf[0] == 0 || remote_addr_buf[0] == 0) {
        fprintf(stderr, "Could not get required connection information\n");
        return MNL_CB_ERROR;
    } else {
        if (strcmp(local_addr_buf, "0.0.0.0") == 0 || strcmp(remote_addr_buf, "0.0.0.0") == 0) {
            //not printing for 0.0.0.0
            //IPv4, empty
            return MNL_CB_OK;
        }
        if (strcmp(local_addr_buf, "::") == 0 || strcmp(remote_addr_buf, "::") == 0) {
            //not printing for ::
            //IPv6, empty
            return MNL_CB_OK;
        }
    }

    return 0;
}

static int diag_data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct inet_diag_msg *idm = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[INET_DIAG_MAX + 1] = { 0 };
    struct diag_sockinfo info;
    struct tcp_info *tp = NULL;
    int err;

    if ((err = mnl_attr_parse(nlh, sizeof *idm, diag_data_attr_cb, tb)) != MNL_CB_OK) {
        fprintf(stderr, "Failed to parse netlink message\n");
        return err;
    }

    if ((err = is_localhost(idm)) > 0) {
        return MNL_CB_OK;
    } else if (err < 0) {
        fprintf(stderr, "diag_data_cb: error\n");
        return MNL_CB_ERROR;
    }

    memset(&info, 0, sizeof(struct diag_sockinfo));
    info.state = idm->idiag_state;
    info.local.af = idm->idiag_family;
    info.local.bytelen = (info.local.af == AF_INET ? 4 : 16);
    info.local.bitlen = (info.local.af == AF_INET ? 32 : 128);
    info.local_port = idm->id.idiag_sport;
    info.remote.af = idm->idiag_family;
    info.remote.bytelen = (info.remote.af == AF_INET ? 4 : 16);
    info.remote.bitlen = (info.remote.af == AF_INET ? 32 : 128);
    info.remote_port = idm->id.idiag_dport;
    info.iface = idm->id.idiag_if;
    info.uid = idm->idiag_uid;
    memcpy(info.local.addr, idm->id.idiag_src, info.local.bytelen);
    memcpy(info.remote.addr, idm->id.idiag_dst, info.remote.bytelen);

    if (tb[INET_DIAG_INFO]) {
        tp = mnl_attr_get_payload(tb[INET_DIAG_INFO]);
        //len = mnl_attr_get_payload_len(tb[INET_DIAG_INFO]);
        info.tp = tp;
    }

    if (tb[INET_DIAG_CONG]) {
        info.has_cong_name = TRUE;
        strncpy(info.cong_name,
                mnl_attr_get_str(tb[INET_DIAG_CONG]),
                sizeof(info.cong_name) - 1);
    }

#ifdef GET_BBRX_INFO
    if (tb[INET_DIAG_BBRXINFO]) {
        info.bbrx_info = (struct tcp_bbrx_info*) mnl_attr_get_str(tb[INET_DIAG_BBRXINFO]);
    }
#endif

    if (tb[INET_DIAG_BBRINFO]) {
        info.bbr_info = (struct tcp_bbr_info*) mnl_attr_get_str(tb[INET_DIAG_BBRINFO]);
    }

    diag_dump_sockinfo(&info);
    info.tp = NULL;

    return MNL_CB_OK;
}

void first_task()
{
    if (one_object_array) {
        fprintf(output_file, "[\n");
    }
}

void last_task_before_exit()
{
    fflush(output_file);
    if (one_object_array) {
        fprintf(output_file, "]\n\n\n");
        if (output_file != stdout) {
            fclose(output_file);
            output_file = stdout;
        }
    }
    diag_close_socket(h);
}

void last_task_before_exit_callback(int s)
{
    last_task_before_exit();
    printf("Ctrl-C event received, exiting program...\n");
    exit(1); 
}

void add_signal_handler()
{
    if (one_object_array) {
        struct sigaction sig_int_handler;

        sig_int_handler.sa_handler = last_task_before_exit_callback;
        sigemptyset(&sig_int_handler.sa_mask);
        sig_int_handler.sa_flags = 0;

        sigaction(SIGINT, &sig_int_handler, NULL);
    }
}

void getopt_and_apply(int argc, char *argv[])
{
    int c;
    const char *short_opt = "hlpw:";
    struct option long_opt[] = {
        {"help",          no_argument,       NULL, 'h'},
        {"objbyline",     no_argument,       NULL, 'l'},
        {"pulling",       no_argument,       NULL, 'p'},
        {"outputfile",    required_argument, NULL, 'w'},
        {NULL,            0,                 NULL, 0  }
    };

    while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
        switch (c) {
            case -1:
            case 0:
                break;

            case 'w':
                printf("You entered \"%s\"\n", optarg);
                output_file = fopen (optarg, "a+");
                if (output_file == NULL) {
                    fprintf(stderr, "Cannot open file: %s\n", optarg);
                    fprintf(stderr, "Exiting...\n");
                    exit(-2);
                }
                break;

            case 'l':
                printf("Using object by line option\n");
                one_object_array = FALSE;
                break;

            case 'p':
                printf("Pulling the TCP stats\n");
                pulling = TRUE;
                break;

            case 'h':
                printf("Usage: %s [OPTIONS]\n"
                       "  -w (--outputfile) <file>       output file\n"
                       "  -l (--objbyline)               print single object by line\n"
                       "  -p (--pulling)                 request TCP stat info once and exit\n"
                       "  -h (--help)                    print this help and exit\n"
                       , argv[0]);
                exit(0);

            case ':':
            case '?':
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
                exit(-2);

            default:
                fprintf(stderr, "%s: invalid option -- %c\n", argv[0], c);
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
                exit(-2);
        }
    }
}

void talking_to_kernel(unsigned short int family)
{
    ssize_t count = 0;
    unsigned char sockbuf[BUFSIZE];
    int err;
    unsigned int groups = 0;

    h = diag_open_socket();
    if (h == NULL) {
        fprintf(stderr, "Failed to open netlink socket.");
        exit(-2);
    }
    diag_build_msg(h, buf, family);
    if (pulling) {
        diag_send_msg(h);
    } else {
        add_signal_handler();
        groups |= 1 << (SKNLGRP_INET_TCP_DESTROY  - 1);
        groups |= 1 << (SKNLGRP_INET6_TCP_DESTROY - 1);
        diag_subscribe(h, groups);
    }

    count = mnl_socket_recvfrom(h->mnl, sockbuf, sizeof(sockbuf));
    while (count > 0) {
        err = mnl_cb_run(sockbuf, count, 0, 0, diag_data_cb, NULL);
        if (err <= 0)
            break;
        count = mnl_socket_recvfrom(h->mnl, sockbuf, sizeof(sockbuf));
    }
}

int main(int argc, char *argv[])
{
    init_global_variables();
    getopt_and_apply(argc, argv);
    first_task();
    if (pulling) {
        talking_to_kernel(AF_INET);
        fflush(output_file);
        diag_close_socket(h);
        talking_to_kernel(AF_INET6);
    } else {
        talking_to_kernel(AF_UNSPEC);
    }
    last_task_before_exit();
    return 0;
}

