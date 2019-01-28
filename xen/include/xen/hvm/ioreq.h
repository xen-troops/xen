
#define GET_IOREQ_SERVER(d, id) \
    (d)->arch.hvm.ioreq_server.server[id]

struct hvm_ioreq_server *get_ioreq_server(const struct domain *d,
                                          unsigned int id);

/*
 * Iterate over all possible ioreq servers.
 *
 * NOTE: The iteration is backwards such that more recently created
 *       ioreq servers are favoured in hvm_select_ioreq_server().
 *       This is a semantic that previously existed when ioreq servers
 *       were held in a linked list.
 */
#define FOR_EACH_IOREQ_SERVER(d, id, s) \
    for ( (id) = MAX_NR_IOREQ_SERVERS; (id) != 0; ) \
        if ( !(s = GET_IOREQ_SERVER(d, --(id))) ) \
            continue; \
        else


