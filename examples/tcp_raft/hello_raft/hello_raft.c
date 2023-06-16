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
};

static int g_node_id;
static char* g_host;
static int g_raft_port;
static bool g_is_running;

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
	printf(" -p PORT            Port for Raft peer traffic [default: 9000]\n");
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

static void peer_msg_send(struct hello_cb_context_t *cb_ctx, tpl_node *tn, struct iovec *buf, char *data) {
	peer_msg_serialize(tn, buf, data);
	ssize_t n = spdk_sock_writev(cb_ctx->ctx->sock, buf, 1);
	if (n < 0) {
		SPDK_ERRLOG("error send peer msg\n");
		exit(1);
	}
}

static int
send_handshake_response(struct hello_cb_context_t *cb_ctx, handshake_state_e success, raft_node_t *leader) {
	struct iovec *bufs = calloc(1, sizeof(struct iovec));
	char buf[RAFT_BUFLEN];

	struct msg_t msg = {};
	msg.type = MSG_HANDSHAKE_RESPONSE;
    msg.hsr.success = success;
    msg.hsr.leader_port = 0;
	msg.hsr.node_id = cb_ctx->ctx->node_id;

	if (leader) {
		struct peer_connection_t *leader_conn = raft_get_udata(leader);
		if (leader_conn) {
			msg.hsr.leader_port = leader_conn->raft_port;
			memcpy(msg.hsr.leader_host, cb_ctx->peer_conn->addr, sizeof(msg.hsr.leader_host));
		}
	}

	peer_msg_send(cb_ctx, tpl_map("S(I$(IIIIs))", &msg), bufs, buf);

	return 0;
}

static int
append_cfg_change(struct hello_cb_context_t *cb_ctx, raft_logtype_e change_type, int raft_port, int node_id) {
	struct entry_cfg_change_t *change = calloc(1, sizeof(*change));
    change->raft_port = raft_port;
	change->node_id = node_id;
    strcpy(change->host, cb_ctx->peer_conn->addr);
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

static int deserialize_and_handle_msg(struct hello_cb_context_t *cb_ctx, struct iovec *iov) {
	cb_ctx->ctx->bytes_in += iov->iov_len;
	struct msg_t m;
    int e;

	if (cb_ctx->peer_conn->n_expected_entries > 0) {
		msg_entry_t entry;
		deserialize_appendentries_payload(&entry, iov);
		cb_ctx->peer_conn->ae.ae.entries = &entry;
		struct msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
		e = raft_recv_appendentries(
			cb_ctx->ctx->raft,
			cb_ctx->peer_conn->node,
			&cb_ctx->peer_conn->ae.ae,
			&msg.aer);
		char buf[RAFT_BUFLEN];
		struct iovec *bufs = calloc(1, sizeof(struct iovec));
		peer_msg_send(cb_ctx, tpl_map("S(I$(IIII))", &msg), bufs, buf);
		cb_ctx->peer_conn->n_expected_entries = 0;
		return 0;
	}

	void *img = iov->iov_base;
	size_t sz = iov->iov_len;

	tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &m);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

	switch (m.type) {
	case MSG_HANDSHAKE: {
		struct peer_connection_t *nconn = find_connection(
			cb_ctx->ctx->conns, cb_ctx->peer_conn->addr, m.hs.raft_port);
			if (nconn && cb_ctx->peer_conn != nconn) {
				delete_connection(cb_ctx->ctx->conns, nconn);
			}

			cb_ctx->peer_conn->connection_status = CONNECTED;
			cb_ctx->peer_conn->raft_port = m.hs.raft_port;

			raft_node_t *leader = raft_get_current_leader_node(cb_ctx->ctx->raft);
			raft_node_t *node = raft_get_node(cb_ctx->ctx->raft, m.hs.node_id);
			if (node) {
				raft_node_set_udata(node, cb_ctx->peer_conn);
				cb_ctx->peer_conn->node = node;
			}

			if (!leader) {
				return send_handshake_response(cb_ctx->peer_conn, HANDSHAKE_FAILURE, NULL);
			} else if (raft_node_get_id(leader) != cb_ctx->ctx->node_id) {
				return send_handshake_response(cb_ctx->peer_conn, HANDSHAKE_FAILURE, leader);
			} else if (node) {
				return send_handshake_response(cb_ctx->peer_conn, HANDSHAKE_SUCCESS, NULL);
			} else {
				e = append_cfg_change(cb_ctx, RAFT_LOGTYPE_ADD_NONVOTING_NODE, m.hs.raft_port, m.hs.node_id);
				if (e != 0) {
					return send_handshake_response(cb_ctx->peer_conn, HANDSHAKE_FAILURE, NULL);
				}
				return send_handshake_response(cb_ctx->peer_conn, HANDSHAKE_SUCCESS, NULL);
			}
	}
	}
}

static void hello_raft_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock) {
	int rc;
	struct hello_cb_context_t *ctx = arg;
	struct iovec iov = {};
	ssize_t n;
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
		deserialize_and_handle_msg(ctx, &iov);
	}

	/* Connection closed */
	SPDK_NOTICELOG("Connection closed\n");
	spdk_sock_group_remove_sock(group, sock);
	spdk_sock_close(&sock);
}

static int hello_raft_accept_poll(void* arg) {
	struct hello_context_t *ctx = arg;
	struct spdk_sock *sock;
	int rc;
	int count = 0;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t cport, sport;

	if (!g_is_running) {
		// TODO: hello_raft_quit(ctx, 0);
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

			struct hello_cb_context_t *cb_ctx = calloc(1, sizeof(struct hello_cb_context_t));
			cb_ctx->ctx = ctx;
			cb_ctx->peer_conn = new_connection(ctx);
			memcpy(cb_ctx->peer_conn->addr, caddr, ADDR_STR_LEN);
			rc = spdk_sock_group_add_sock(ctx->group, sock,
							  hello_raft_cb, cb_ctx);
		}

		// TODO: hello_raft_cb
	}
}

static void hello_start(void *arg1) {
	struct hello_context_t *ctx = arg1;
	int rc;

	SPDK_NOTICELOG("Successfully started the application\n");

	struct spdk_sock_impl_opts impl_opts;
	size_t impl_opts_size = sizeof(impl_opts);
	struct spdk_sock_opts opts;
	static char psk[SPDK_TLS_PSK_MAX_LEN] = {};
	char *unhexlified;

	spdk_sock_impl_get_opts(HELLO_RAFT_SOCK_IMPL, &impl_opts, &impl_opts_size);
	impl_opts.enable_ktls = false;
	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.impl_opts = &impl_opts;
	opts.impl_opts_size = sizeof(impl_opts);

	ctx->sock = spdk_sock_listen_ext(ctx->host, ctx->raft_port, HELLO_RAFT_SOCK_IMPL, &opts);
	if (ctx->sock == NULL) {
		SPDK_ERRLOG("Cannot create server socket\n");
		return -1;
	}

	SPDK_NOTICELOG("Listening connection on %s:%d with sock_impl(%s)\n", ctx->host, ctx->raft_port,
			   HELLO_RAFT_SOCK_IMPL);
	ctx->group = spdk_sock_group_create(NULL);
	if (ctx->group == NULL) {
		SPDK_ERRLOG("Cannot create sock group\n");
		spdk_sock_close(&ctx->sock);
		return -1;
	}

	ctx->buf = calloc(1, BUFFER_SIZE);
	if (ctx->buf == NULL) {
		SPDK_ERRLOG("Cannot allocate memory for sock group\n");
		spdk_sock_close(&ctx->sock);
		return -1;
	}

	spdk_sock_group_provide_buf(ctx->group, ctx->buf, BUFFER_SIZE, NULL);

	g_is_running = true;

	/* TODO:
	ctx->poller_in = SPDK_POLLER_REGISTER(hello_sock_accept_poll, ctx,
						  ACCEPT_TIMEOUT_US);
	ctx->poller_out = SPDK_POLLER_REGISTER(hello_sock_group_poll, ctx, 0);
	 */

	return 0;
}

int main(int argc, char **argv) {
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t hello_context = {};
	hello_context.raft = raft_new();

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_raft";

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "I", NULL, hello_raft_parse_arg,
					hello_raft_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}
	hello_context.node_id = g_node_id;
	hello_context.host = g_host;
	hello_context.raft_port = g_raft_port;

	struct spdk_sock_impl_opts impl_opts = {};
	size_t len = sizeof(impl_opts);
	spdk_sock_impl_set_opts(HELLO_RAFT_SOCK_IMPL, &impl_opts, len);

	raft_add_node(hello_context.raft, NULL, hello_context.node_id, 1);

}
