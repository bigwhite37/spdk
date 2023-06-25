#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"

#include "spdk/sock.h"
#include "spdk/hexlify.h"
#include "spdk/nvmf.h"

#include "raft/raft.h"
#include "tpl/tpl.h"

#define HELLO_RAFT_SOCK_IMPL "posix"
#define ACCEPT_TIMEOUT_US 1000
#define CLOSE_TIMEOUT_US 1000000
#define BUFFER_SIZE 1024
#define RAFT_BUFLEN 512
#define ADDR_STR_LEN INET6_ADDRSTRLEN
#define IP_STR_LEN 16
#define PERIOD_MSEC 1000

typedef enum {
    HANDSHAKE_FAILURE,
    HANDSHAKE_SUCCESS,
} handshake_state_e;

typedef enum {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
} conn_status_e;


typedef enum
{
    /** Handshake is a special non-raft message type
     * We send a handshake so that we can identify ourselves to our peers */
    MSG_HANDSHAKE,
    /** Successful responses mean we can start the Raft periodic callback */
    MSG_HANDSHAKE_RESPONSE,
    /** Tell leader we want to leave the cluster */
    /* When instance is ctrl-c'd we have to gracefuly disconnect */
    MSG_LEAVE,
    /* Receiving a leave response means we can shutdown */
    MSG_LEAVE_RESPONSE,
    MSG_REQUESTVOTE,
    MSG_REQUESTVOTE_RESPONSE,
    MSG_APPENDENTRIES,
    MSG_APPENDENTRIES_RESPONSE,
} peer_message_type_e;

struct msg_handshake_t {
    int raft_port;
    int http_port;
    int node_id;
};

struct msg_handshake_response_t {
    int success;

    /* leader's Raft port */
    int leader_port;

    /* the responding node's HTTP port */
    int http_port;

    /* my Raft node ID.
     * Sometimes we don't know who we did the handshake with */
    int node_id;

    char leader_host[IP_STR_LEN];
};

struct msg_t {
    int type;
    union
    {
        struct msg_handshake_t hs;
        struct msg_handshake_response_t hsr;
        msg_requestvote_t rv;
        msg_requestvote_response_t rvr;
        msg_appendentries_t ae;
        msg_appendentries_response_t aer;
    };
    int padding[100];
};

struct entry_cfg_change_t {
    int raft_port;
    int http_port;
    int node_id;
    char host[IP_STR_LEN];
};

struct peer_connection_t {
	struct spdk_sock *sock;
	char addr[ADDR_STR_LEN];
	int raft_port;
	tpl_gather_t *gt;
	conn_status_e connection_status;
	raft_node_t *node;
	int n_expected_entries;
	struct msg_t ae;
	struct peer_connection_t *next;
};

struct hello_context_t {
	int node_id;
	char* host;
	int raft_port;
	struct spdk_sock *sock;
	struct spdk_sock_group *group;
	void *buf;
	struct spdk_poller *poller_in;
	struct spdk_poller *poller_out;
	struct spdk_poller *period_poller;
	struct spdk_poller *time_out;
	int rc;
	int bytes_in;
	int bytes_out;
	raft_server_t *raft;
	struct peer_connection_t *conns;
};

struct hello_cb_context_t {
	struct peer_connection_t *peer_conn;
	struct hello_context_t *ctx;
	struct peer_connection_t *accepted_conn;
};

static int g_node_id;
static char* g_host;
static int g_raft_port;
static bool g_is_running;
static int g_is_start;
static int g_is_join;
static int g_is_leave;
static char* g_join_peer;
struct hello_cb_context_t* g_cb_ctx;

static void connect_to_peer_at_host(
	struct hello_cb_context_t *cb_ctx,
	struct peer_connection_t *conn,
	char* host, int port);

static struct peer_connection_t *new_connection(struct hello_context_t *ctx) {
	struct peer_connection_t *conn = calloc(1, sizeof(struct peer_connection_t));
	conn->next = ctx->conns;
	ctx->conns = conn;
	return conn;
}

static struct peer_connection_t *find_connection(struct peer_connection_t *conns, const char *host, int port) {
	struct peer_connection_t *conn;
	for (conn = conns;
		 conn && (0 != strcmp(host, conn->addr) || conn->raft_port != port);
		 conn = conn->next);
	return conn;
}

static void delete_connection(struct peer_connection_t *conns, struct peer_connection_t *conn) {
	struct peer_connection_t *prev;
	if (conns == conn) {
		conns = conn->next;
	} else if (conns != conn) {
		for (prev = conns; prev->next != conn; prev = prev->next);
		prev->next = conn->next;
	} else {
		SPDK_ERRLOG("Cannot find the deleted connection\n");
		assert(0);
	}

	if (conn->node) {
		raft_node_set_udata(conn->node, NULL);
	}

	free(conn);
}

static void hello_raft_usage(void)
{
	printf(" -I ID              This server's manually set Raft ID\n");
	printf(" -H HOST            Host to listen on [default: 127.0.0.1]\n");
	printf(" -P PORT            Port for Raft peer traffic [default: 9000]\n");
    printf(" -S                 Create a new cluster\n");
    printf(" -J PEER            Join cluster via peer\n");
    printf(" -Q                 Leave cluster\n");
}

static int hello_raft_parse_arg(int ch, char *arg) {
	switch (ch) {
	case 'I':
		g_node_id = (int)spdk_strtol(arg, 10);
		break;
	case 'H':
		g_host = arg;
		break;
	case 'P':
		g_raft_port = (int)spdk_strtol(arg, 10);
		break;
    case 'S':
        g_is_start = 1;
        break;
    case 'J':
        g_is_join = 1;
        g_join_peer = arg;
        break;
    case 'Q':
        g_is_leave = 1;
        break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void deserialize_appendentries_payload(msg_entry_t *out, struct iovec *iov) {
	tpl_bin tb;
	tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, iov->iov_base, iov->iov_len),
						&out->id,
						&out->term,
						&out->type,
						&tb);
	tpl_load(tn, TPL_MEM, iov->iov_base, iov->iov_len);
	tpl_unpack(tn, 0);
	out->data.buf = tb.addr;
	out->data.len = tb.sz;
}

static size_t peer_msg_serialize(tpl_node *tn, struct iovec *buf, char* data) {
	size_t sz;
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_GETSIZE, &sz);
    tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, data, RAFT_BUFLEN);
    tpl_free(tn);
	buf->iov_base = data;
	buf->iov_len = sz;
	return sz;
}

static void peer_msg_send(struct peer_connection_t *conn, tpl_node *tn, struct iovec *buf, char *data) {
	peer_msg_serialize(tn, buf, data);
	ssize_t n = spdk_sock_writev(conn->sock, buf, 1);
	if (n < 0) {
		SPDK_ERRLOG("error send peer msg\n");
		exit(1);
	}
}

static int
send_handshake_response(struct peer_connection_t *conn, handshake_state_e success, raft_node_t *leader, int node_id) {
	struct iovec bufs;
	char buf[RAFT_BUFLEN];

	struct msg_t msg = {};
	msg.type = MSG_HANDSHAKE_RESPONSE;
    msg.hsr.success = success;
    msg.hsr.leader_port = 0;
	msg.hsr.node_id = node_id;

	if (leader) {
		struct peer_connection_t *leader_conn = raft_get_udata(leader);
		if (leader_conn) {
			msg.hsr.leader_port = leader_conn->raft_port;
			memcpy(msg.hsr.leader_host, conn->addr, sizeof(msg.hsr.leader_host));
		}
	}

	peer_msg_send(conn, tpl_map("S(I$(IIIIs))", &msg), &bufs, buf);

	return 0;
}

static int
append_cfg_change(struct hello_cb_context_t *cb_ctx, raft_logtype_e change_type, char *host, int raft_port, int node_id) {
	struct entry_cfg_change_t *change = calloc(1, sizeof(*change));
    change->raft_port = raft_port;
	change->node_id = node_id;
    strcpy(change->host, host);
    change->host[IP_STR_LEN - 1] = 0;

	msg_entry_t entry;
    entry.id = rand();
    entry.data.buf = (void*)change;
    entry.data.len = sizeof(*change);
    entry.type = change_type;

	msg_entry_response_t r;
    int e = raft_recv_entry(cb_ctx->ctx->raft, &entry, &r);
    if (0 != e) { return -1; }
    return 0;
}

static void send_handshake(struct peer_connection_t *conn, int node_id) {
	struct iovec iov;
	char buf[RAFT_BUFLEN];
	struct msg_t msg = {};
	msg.type = MSG_HANDSHAKE;
	msg.hs.raft_port = g_raft_port;
	msg.hs.node_id = node_id;
	peer_msg_send(conn, tpl_map("S(I$(IIII))", &msg), &iov, buf);
}

static int deserialize_and_handle_msg(struct peer_connection_t *peer_conn, struct hello_cb_context_t *cb_ctx, struct iovec *iov) {
	cb_ctx->ctx->bytes_in += iov->iov_len;
	struct msg_t m;
    int e;

	if (peer_conn->n_expected_entries > 0) {
		msg_entry_t entry;
		deserialize_appendentries_payload(&entry, iov);
		peer_conn->ae.ae.entries = &entry;
		struct msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
		e = raft_recv_appendentries(
			cb_ctx->ctx->raft,
			peer_conn->node,
			&peer_conn->ae.ae,
			&msg.aer);
		char buf[RAFT_BUFLEN];
		struct iovec bufs;
		peer_msg_send(peer_conn, tpl_map("S(I$(IIII))", &msg), &bufs, buf);
		peer_conn->n_expected_entries = 0;
		return 0;
	}

    char buf[RAFT_BUFLEN];
	struct iovec bufs;
	void *img = iov->iov_base;
	size_t sz = iov->iov_len;

	tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &m);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

	switch (m.type) {
	case MSG_HANDSHAKE: {
		struct peer_connection_t *nconn = find_connection(
			cb_ctx->ctx->conns, peer_conn->addr, m.hs.raft_port);
        if (nconn && peer_conn != nconn) {
            delete_connection(cb_ctx->ctx->conns, nconn);
        }

        peer_conn->connection_status = CONNECTED;
        peer_conn->raft_port = m.hs.raft_port;

        raft_node_t *leader = raft_get_current_leader_node(cb_ctx->ctx->raft);
        raft_node_t *node = raft_get_node(cb_ctx->ctx->raft, m.hs.node_id);
        if (node) {
            raft_node_set_udata(node, peer_conn);
            peer_conn->node = node;
        }

        if (!leader) {
            return send_handshake_response(peer_conn, HANDSHAKE_FAILURE, NULL, cb_ctx->ctx->node_id);
        } else if (raft_node_get_id(leader) != cb_ctx->ctx->node_id) {
            return send_handshake_response(peer_conn, HANDSHAKE_FAILURE, leader, cb_ctx->ctx->node_id);
        } else if (node) {
            return send_handshake_response(peer_conn, HANDSHAKE_SUCCESS, NULL, cb_ctx->ctx->node_id);
        } else {
            e = append_cfg_change(cb_ctx, RAFT_LOGTYPE_ADD_NONVOTING_NODE, peer_conn->addr, m.hs.raft_port, m.hs.node_id);
            if (e != 0) {
                return send_handshake_response(peer_conn, HANDSHAKE_FAILURE, NULL, cb_ctx->ctx->node_id);
            }
            return send_handshake_response(peer_conn, HANDSHAKE_SUCCESS, NULL, cb_ctx->ctx->node_id);
        }
        break;
	}
    case MSG_HANDSHAKE_RESPONSE: {
        if (m.hsr.success == 0) {
            if (m.hsr.leader_port) {
                struct peer_connection_t* nconn = find_connection(
                    cb_ctx->ctx->conns, peer_conn->addr, m.hsr.leader_port);
				if (!nconn) {
					nconn = new_connection(cb_ctx->ctx);
					SPDK_NOTICELOG("Redirecting to %s:%d...\n", m.hsr.leader_host, m.hsr.leader_port);
					connect_to_peer_at_host(cb_ctx, nconn, m.hsr.leader_host, m.hsr.leader_port);
				}
            }
        } else {
			SPDK_NOTICELOG("Connected to leader: %s:%d\n",
				peer_conn->addr, peer_conn->raft_port);

			if (!peer_conn->node) {
				peer_conn->node = raft_get_node(cb_ctx->ctx->raft, m.hsr.node_id);
			}
		}
		break;
    }
	case MSG_LEAVE: {
		if (!peer_conn->node) {
			SPDK_ERRLOG("ERROR: no node\n");
			return 0;
		}
		int e = append_cfg_change(
			cb_ctx, RAFT_LOGTYPE_REMOVE_NODE, peer_conn->addr, peer_conn->raft_port, raft_node_get_id(peer_conn->node));
		if (e != 0) {
			SPDK_ERRLOG("ERROR: Leave request failed\n");
		}
		break;
	}
	case MSG_LEAVE_RESPONSE: {
		SPDK_NOTICELOG("Shutdown complete. Quitting...\n");
		exit(0);
		break;
	}
	case MSG_REQUESTVOTE: {
		struct msg_t msg = { .type = MSG_REQUESTVOTE_RESPONSE };
		raft_recv_requestvote(cb_ctx->ctx->raft, peer_conn->node, &m.rv, &msg.rvr);
        peer_msg_send(peer_conn, tpl_map("S(I$(II))", &msg), &bufs, buf);
        break;
	}
    case MSG_APPENDENTRIES: {
        if (0 < m.ae.n_entries) {
            peer_conn->n_expected_entries = m.ae.n_entries;
            memcpy(&peer_conn->ae, &m, sizeof(struct msg_t));
            return 0;
        }

        struct msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        raft_recv_appendentries(cb_ctx->ctx->raft, peer_conn->node, &m.ae, &msg.aer);
        peer_msg_send(peer_conn, tpl_map("S(I$(IIII))", &msg), &bufs, buf);
        break;
    }
    case MSG_APPENDENTRIES_RESPONSE: {
        raft_recv_appendentries_response(cb_ctx->ctx->raft, peer_conn->node, &m.aer);
        // FIXME: uv_cond_signal(&sv->appendentries_received);
        break;
    }
    default: {
        SPDK_ERRLOG("unknown msg\n");
        exit(0);
    }
	}

    return 0;
}

static void on_connection_accepted_by_peer(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock) {
    struct hello_cb_context_t *cb_ctx = arg;
	send_handshake(cb_ctx->accepted_conn, cb_ctx->ctx->node_id);
	cb_ctx->accepted_conn->connection_status = CONNECTED;

	int rc;
	struct iovec iov = {};
	void *user_ctx;

	rc = spdk_sock_recv_next(sock, &iov.iov_base, &user_ctx);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		if (errno != ENOTCONN && errno != ECONNRESET) {
			SPDK_ERRLOG("spdk_sock_recv_zcopy() failed, errno %d: %s\n",
				    errno, spdk_strerror(errno));
		}
	}

	iov.iov_len = rc;

	if (iov.iov_len > 0) {
		deserialize_and_handle_msg(cb_ctx->accepted_conn, cb_ctx, &iov);
	}
}

static void connection_set_peer(struct peer_connection_t *conn, char *host, int port) {
	conn->raft_port = port;
	memcpy(conn->addr, host, sizeof(conn->addr));
	SPDK_NOTICELOG("set connection to %s:%d\n", host, port);
}

static void connect_to_peer(struct hello_cb_context_t *cb_ctx, struct peer_connection_t *conn) {
	struct spdk_sock_impl_opts impl_opts;
	size_t impl_opts_size = sizeof(impl_opts);
	struct spdk_sock_opts opts;

	spdk_sock_impl_get_opts(HELLO_RAFT_SOCK_IMPL, &impl_opts, &impl_opts_size);
	impl_opts.enable_ktls = false;
	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.impl_opts = &impl_opts;
	opts.impl_opts_size = sizeof(impl_opts);

	SPDK_NOTICELOG("Connecting to the server on %s:%d\n", conn->addr, conn->raft_port);
	conn->sock = spdk_sock_connect_ext(conn->addr, conn->raft_port, HELLO_RAFT_SOCK_IMPL, &opts);
	if (conn->sock == NULL) {
		SPDK_ERRLOG("Cannot create socket connecting to %s:%d\n", conn->addr, conn->raft_port);
		exit(1);
	}
	cb_ctx->accepted_conn = conn;

	spdk_sock_group_add_sock(cb_ctx->ctx->group, conn->sock,
						on_connection_accepted_by_peer, cb_ctx);
}

static void connect_to_peer_at_host(
	struct hello_cb_context_t *cb_ctx,
	struct peer_connection_t *conn,
	char* host, int port) {
	connection_set_peer(conn, host, port);
	connect_to_peer(cb_ctx, conn);
}

static int __connect_if_needed(struct hello_cb_context_t *cb_ctx, struct peer_connection_t *conn) {
    if (conn->connection_status != CONNECTED) {
        if (conn->connection_status == DISCONNECTED) {
            connect_to_peer(cb_ctx, conn);
        }
        return -1;
    }
    return 0;
}

static void __send_leave(struct peer_connection_t *conn) {
    struct iovec bufs[1];
    char buf[RAFT_BUFLEN];
    struct msg_t msg = {};
    msg.type = MSG_LEAVE;
    peer_msg_send(conn, tpl_map("S(I)", &msg), &bufs[0], buf);
}

static int __send_leave_response(struct peer_connection_t *conn) {
    if (!conn) {
        SPDK_ERRLOG("no connection???\n");
        return -1;
    }

    if (!conn->sock) {
        SPDK_ERRLOG("no connected socket???\n");
        return -1;
    }

    struct iovec bufs[1];
    char buf[RAFT_BUFLEN];
    struct msg_t msg;
    msg.type = MSG_LEAVE_RESPONSE;
    peer_msg_send(conn, tpl_map("S(I)", &msg), &bufs[0], buf);

    return 0;
}

static int __offer_cfg_change(
    struct hello_cb_context_t *cb_ctx, raft_server_t *raft, const unsigned char *data, raft_logtype_e change_type) {

    struct entry_cfg_change_t *change = (void*)data;
    struct peer_connection_t *conn = find_connection(cb_ctx->ctx->conns, change->host, change->raft_port);

    if (RAFT_LOGTYPE_REMOVE_NODE == change_type) {
        raft_remove_node(raft, raft_get_node(cb_ctx->ctx->raft, change->node_id));
        if (conn) {
            conn->node = NULL;
        }
        return 0;
    }

    if (!conn) {
        conn = new_connection(cb_ctx->ctx);
        connection_set_peer(conn, change->host, change->raft_port);
    }
    int is_self = change->node_id == cb_ctx->ctx->node_id;

    switch (change_type) {
    case RAFT_LOGTYPE_ADD_NONVOTING_NODE:
        conn->node = raft_add_non_voting_node(raft, conn, change->node_id, is_self);
        break;
    case RAFT_LOGTYPE_ADD_NODE:
        conn->node = raft_add_node(raft, conn, change->node_id, is_self);
        break;
    default:
        SPDK_ERRLOG("unknown change type\n");
        exit(-1);
    }

    raft_node_set_udata(conn->node, conn);

    return 0;
}

static int
__raft_send_requestvote(raft_server_t *raft, void *user_data, raft_node_t *node, msg_requestvote_t *m) {
    struct hello_cb_context_t *cb_ctx = user_data;
    struct peer_connection_t *conn = raft_node_get_udata(node);

    int e = __connect_if_needed(cb_ctx, conn);
    if (e == -1) {
        SPDK_ERRLOG("Error in raft_send_requestvote() when connecting\n");
        return 0;
    }

    struct iovec bufs;
    char buf[RAFT_BUFLEN];
    struct msg_t msg = {};
    msg.type = MSG_REQUESTVOTE,
    msg.rv = *m;
    peer_msg_send(conn, tpl_map("S(I$(IIII))", &msg), &bufs, buf);
    return 0;
}

static int
__raft_send_appendentries(raft_server_t *raft, void *user_data, raft_node_t *node, msg_appendentries_t *m) {
    struct hello_cb_context_t *cb_ctx = user_data;
    struct peer_connection_t *conn = raft_node_get_udata(node);

    int e = __connect_if_needed(cb_ctx, conn);
    if (e == -1) {
        SPDK_ERRLOG("Error in raft_send_requestvote() when connecting\n");
        return 0;
    }

    char buf[RAFT_BUFLEN], *ptr = buf;
    struct msg_t msg = {};
    msg.type = MSG_APPENDENTRIES;
    msg.ae.term = m->term;
    msg.ae.prev_log_idx   = m->prev_log_idx;
    msg.ae.prev_log_term = m->prev_log_term;
    msg.ae.leader_commit = m->leader_commit;
    msg.ae.n_entries = m->n_entries;

    struct iovec bufs[3];
    ptr += peer_msg_serialize(tpl_map("S(I$(IIIII))", &msg), bufs, ptr);

    if (0 < m->n_entries) {
        tpl_bin tb = {
            .sz   = m->entries[0].data.len,
            .addr = m->entries[0].data.buf
        };

        tpl_node *tn = tpl_map("IIIB",
                &m->entries[0].id,
                &m->entries[0].term,
                &m->entries[0].type,
                &tb);
        size_t sz;
        tpl_pack(tn, 0);
        tpl_dump(tn, TPL_GETSIZE, &sz);
        e = tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, ptr, RAFT_BUFLEN);
        assert(0 == e);
        bufs[1].iov_len = sz;
        bufs[1].iov_base = ptr;
        e = spdk_sock_writev(conn->sock, bufs, 2);
        if (e < 0) {
            SPDK_ERRLOG("send append entries error\n");
        }

        tpl_free(tn);
    } else {
        e = spdk_sock_writev(conn->sock, bufs, 1);
        if (e < 0) {
            SPDK_ERRLOG("send append entries error\n");
        }
    }

    return 0;
}

static int __raft_applylog(raft_server_t* raft, void *udata, raft_entry_t *ety) {
    SPDK_NOTICELOG("do raft apply log\n");
    struct hello_cb_context_t *cb_ctx = udata;

    if (raft_entry_is_cfg_change(ety)) {
        struct entry_cfg_change_t *change = ety->data.buf;
        if (RAFT_LOGTYPE_REMOVE_NODE != ety->type || !raft_is_leader(cb_ctx->ctx->raft)) {
            goto commit;
        }

        struct peer_connection_t* conn = find_connection(
            cb_ctx->ctx->conns, change->host, change->raft_port);
        __send_leave_response(conn);
        goto commit;
    }

    SPDK_NOTICELOG("[raft apply log] do mdb_put()\n");

commit:
    SPDK_NOTICELOG("[raft apply log] do commit\n");

    return 0;
}

static int __raft_persist_vote(raft_server_t* raft, void *udata, const int voted_for) {
    SPDK_NOTICELOG("do raft persist vote\n");
    return 0;
}

static int __raft_persist_term(raft_server_t* raft, void *udata, const int current_term) {
    SPDK_NOTICELOG("do raft persist term\n");
    return 0;
}

static int __raft_logentry_offer(raft_server_t *raft, void *udata, raft_entry_t *ety, int ety_idx) {
    SPDK_NOTICELOG("do __raft_logentry_offer()\n");
    struct hello_cb_context_t *cb_ctx = udata;
    if (raft_entry_is_cfg_change(ety)) {
        __offer_cfg_change(cb_ctx, raft, ety->data.buf, ety->type);
    }

    SPDK_NOTICELOG("[__raft_logentry_offer] begin txn\n");
    struct iovec bufs[1];
    char buf[RAFT_BUFLEN];
    peer_msg_serialize(tpl_map("S(III)", ety), bufs, buf);

    SPDK_NOTICELOG("[__raft_logentry_offer] run txn\n");
    SPDK_NOTICELOG("[__raft_logentry_offer] commit txn\n");

    return 0;
}

static int __raft_logentry_poll(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    int ety_idx) {
    SPDK_NOTICELOG("do __raft_logentry_poll()\n");
    return 0;
}

static int __raft_logentry_pop(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    int ety_idx) {
    SPDK_NOTICELOG("do __raft_logentry_pop()\n");
    return 0;
}

static void __raft_node_has_sufficient_logs(
    raft_server_t* raft,
    void *udata,
    raft_node_t* node) {
    struct peer_connection_t* conn = raft_node_get_udata(node);
    struct hello_cb_context_t *cb_ctx = udata;

    append_cfg_change(cb_ctx, RAFT_LOGTYPE_ADD_NODE, conn->addr, conn->raft_port, raft_node_get_id(conn->node));
}

static void __raft_log(raft_server_t* raft, raft_node_t* node, void *udata, const char *buf) {
    SPDK_NOTICELOG("do __raft_log()\n");
}

raft_cbs_t raft_funcs = {
    .send_requestvote            = __raft_send_requestvote,
    .send_appendentries          = __raft_send_appendentries,
    .applylog                    = __raft_applylog,
    .persist_vote                = __raft_persist_vote,
    .persist_term                = __raft_persist_term,
    .log_offer                   = __raft_logentry_offer,
    .log_poll                    = __raft_logentry_poll,
    .log_pop                     = __raft_logentry_pop,
    .node_has_sufficient_logs    = __raft_node_has_sufficient_logs,
    .log                         = __raft_log,
};

static void __int_handler(int dummy) {
    raft_node_t* leader = raft_get_current_leader_node(g_cb_ctx->ctx->raft);
    if (leader) {
        if (raft_node_get_id(leader) == g_cb_ctx->ctx->node_id) {
            SPDK_NOTICELOG("I'm the leader, I can't leave the cluster...\n");
            return;
        }

        struct peer_connection_t *leader_conn = raft_node_get_udata(leader);
        if (leader_conn) {
            SPDK_NOTICELOG("Leaving cluster...\n");
            __send_leave(leader_conn);
            return;
        }
    }

    SPDK_NOTICELOG("Try again no leader at the moment...\n");
}

// aka on_peer_connection
static void hello_raft_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock) {
	int rc;
	struct hello_cb_context_t *cb_ctx = arg;
	struct iovec iov = {};
	void *user_ctx;

	rc = spdk_sock_recv_next(sock, &iov.iov_base, &user_ctx);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		if (errno != ENOTCONN && errno != ECONNRESET) {
			SPDK_ERRLOG("spdk_sock_recv_zcopy() failed, errno %d: %s\n",
				    errno, spdk_strerror(errno));
		}
	}

	iov.iov_len = rc;

	if (iov.iov_len > 0) {
		deserialize_and_handle_msg(cb_ctx->peer_conn, cb_ctx, &iov);
	}

	/* Connection closed */
	// SPDK_NOTICELOG("Connection closed\n");
	// spdk_sock_group_remove_sock(group, sock);
	// spdk_sock_close(&sock);
}

static int hello_raft_close_timeout_poll(void *arg) {
    struct hello_context_t *ctx = arg;
    SPDK_NOTICELOG("Connection closed\n");

    free(ctx->buf);

    spdk_poller_unregister(&ctx->time_out);
	spdk_poller_unregister(&ctx->poller_in);
	spdk_sock_close(&ctx->sock);
	spdk_sock_group_close(&ctx->group);

	spdk_app_stop(0);
	return SPDK_POLLER_BUSY;
}

static int hello_raft_quit(struct hello_context_t *ctx) {
    spdk_poller_unregister(&ctx->poller_out);
    if (!ctx->time_out) {
        ctx->time_out = SPDK_POLLER_REGISTER(hello_raft_close_timeout_poll, ctx,
                            CLOSE_TIMEOUT_US);
    }

    return 0;
}

static int hello_raft_accept_poll(void* arg) {
	struct hello_cb_context_t *cb_ctx = arg;
    struct hello_context_t *ctx = cb_ctx->ctx;
	struct spdk_sock *sock;
	int rc;
	int count = 0;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t cport, sport;

	if (!g_is_running) {
		hello_raft_quit(ctx);
		return SPDK_POLLER_IDLE;
	}

	while (1) {
		sock = spdk_sock_accept(ctx->sock);
		if (sock != NULL) {
			rc = spdk_sock_getaddr(sock, saddr, sizeof(saddr), &sport, caddr, sizeof(caddr), &cport);
			if (rc < 0) {
				SPDK_ERRLOG("Cannot get connection addresses\n");
				spdk_sock_close(&sock);
				return SPDK_POLLER_IDLE;
			}

			SPDK_NOTICELOG("Accepting a new connection from (%s, %hu) to (%s, %hu)\n",
					   caddr, cport, saddr, sport);

			cb_ctx->peer_conn = new_connection(ctx);
			memcpy(cb_ctx->peer_conn->addr, caddr, ADDR_STR_LEN);
			rc = spdk_sock_group_add_sock(ctx->group, sock,
							  hello_raft_cb, cb_ctx);

            if (rc < 0) {
                spdk_sock_close(&sock);
                SPDK_ERRLOG("failed\n");
                break;
            }
            count++;
		} else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                SPDK_ERRLOG("accept error(%d): %s\n", errno, spdk_strerror(errno));
            }
            break;
        }
	}

    return count > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int hello_raft_group_poll(void *arg) {
    struct hello_context_t *ctx = arg;
    int rc;

    rc = spdk_sock_group_poll(ctx->group);
    if (rc < 0) {
        SPDK_ERRLOG("Failed to poll sock_group=%p\n", ctx->group);
    }

    return rc > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int periodic(void *arg) {
    struct hello_cb_context_t *cb_ctx = arg;
    raft_periodic(cb_ctx->ctx->raft, PERIOD_MSEC);

    if (g_is_leave) {
        raft_node_t *leader = raft_get_current_leader_node(cb_ctx->ctx->raft);
        if (leader) {
            struct peer_connection_t *leader_conn = raft_node_get_udata(leader);
            assert(raft_node_get_id(leader) != cb_ctx->ctx->node_id);
            __send_leave(leader_conn);
        }
    }

    raft_apply_all(cb_ctx->ctx->raft);

    return SPDK_POLLER_BUSY;
}

static void start_raft_periodic_timer(void *arg) {
    struct hello_cb_context_t *cb_ctx = arg;
    cb_ctx->ctx->period_poller = SPDK_POLLER_REGISTER(periodic, cb_ctx, PERIOD_MSEC);
    raft_set_election_timeout(cb_ctx->ctx->raft, 2000);
}

static void hello_start(void *arg1) {
	struct hello_cb_context_t *cb_ctx = arg1;
    struct hello_context_t *ctx = cb_ctx->ctx;

	SPDK_NOTICELOG("Successfully started the application\n");

	struct spdk_sock_impl_opts impl_opts;
	size_t impl_opts_size = sizeof(impl_opts);
	struct spdk_sock_opts opts;

	spdk_sock_impl_get_opts(HELLO_RAFT_SOCK_IMPL, &impl_opts, &impl_opts_size);
	impl_opts.enable_ktls = false;
	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.impl_opts = &impl_opts;
	opts.impl_opts_size = sizeof(impl_opts);

	ctx->sock = spdk_sock_listen_ext(ctx->host, ctx->raft_port, HELLO_RAFT_SOCK_IMPL, &opts);
	if (ctx->sock == NULL) {
		SPDK_ERRLOG("Cannot create server socket\n");
		return;
	}

	SPDK_NOTICELOG("Listening connection on %s:%d with sock_impl(%s)\n", ctx->host, ctx->raft_port,
			   HELLO_RAFT_SOCK_IMPL);
	ctx->group = spdk_sock_group_create(NULL);
	if (ctx->group == NULL) {
		SPDK_ERRLOG("Cannot create sock group\n");
		spdk_sock_close(&ctx->sock);
		return;
	}

	ctx->buf = calloc(1, BUFFER_SIZE);
	if (ctx->buf == NULL) {
		SPDK_ERRLOG("Cannot allocate memory for sock group\n");
		spdk_sock_close(&ctx->sock);
		return;
	}

	spdk_sock_group_provide_buf(ctx->group, ctx->buf, BUFFER_SIZE, NULL);

	g_is_running = true;

	ctx->poller_in = SPDK_POLLER_REGISTER(hello_raft_accept_poll, cb_ctx,
						  ACCEPT_TIMEOUT_US);
	ctx->poller_out = SPDK_POLLER_REGISTER(hello_raft_group_poll, ctx, 0);

    if (g_is_start || g_is_join) {
        if (g_is_start) {
            raft_become_leader(ctx->raft);
            append_cfg_change(cb_ctx, RAFT_LOGTYPE_ADD_NODE, g_host, g_raft_port, ctx->node_id);
        } else {
            struct peer_connection_t *conn = new_connection(ctx);
            connect_to_peer_at_host(cb_ctx, conn, g_join_peer, g_raft_port);
        }
    } else {
        if (raft_get_num_nodes(ctx->raft) == 1) {
            raft_become_leader(ctx->raft);
        } else {
            for (int i = 0; i < raft_get_num_nodes(ctx->raft); ++i) {
                raft_node_t *node = raft_get_node_from_idx(ctx->raft, i);
                if (raft_node_get_id(node) == ctx->node_id) continue;
                connect_to_peer(cb_ctx, raft_node_get_udata(node));
            }
        }
    }

    start_raft_periodic_timer(arg1);
}

int main(int argc, char **argv) {
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t hello_context = {};
    struct hello_cb_context_t cb_ctx = {};
    cb_ctx.ctx = &hello_context;
    g_cb_ctx = &cb_ctx;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, __int_handler);

	hello_context.raft = raft_new();
    raft_set_callbacks(hello_context.raft, &raft_funcs, &cb_ctx);
    hello_context.node_id = g_node_id;
    hello_context.host = g_host;
	hello_context.raft_port = g_raft_port;
    raft_add_node(hello_context.raft, NULL, hello_context.node_id, 1);

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_raft";

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "I:H:P:SJ:Q", NULL, hello_raft_parse_arg,
					hello_raft_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}

struct spdk_sock_impl_opts impl_opts = {};
	size_t len = sizeof(impl_opts);
	spdk_sock_impl_set_opts(HELLO_RAFT_SOCK_IMPL, &impl_opts, len);
    rc = spdk_app_start(&opts, hello_start, &cb_ctx);
    if (rc) {
		SPDK_ERRLOG("ERROR starting application\n");
	}

    SPDK_NOTICELOG("Exiting from application\n");
    spdk_app_fini();
	return rc;
}
