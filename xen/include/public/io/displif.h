/******************************************************************************
 * displif.h
 *
 * Unified display device I/O interface for Xen guest OSes.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016 EPAM Systems Inc.
 *
 * Authors: Oleksandr Andrushchenko <Oleksandr_Andrushchenko@epam.com>
 *          Oleksandr Grytsov <Oleksandr_Grytsov@epam.com>
 */

#ifndef __XEN_PUBLIC_IO_DISPLIF_H__
#define __XEN_PUBLIC_IO_DISPLIF_H__

#include "ring.h"
#include "../grant_table.h"

/******************************************************************************
 * Main features provided by the protocol
 ******************************************************************************
 * This protocol aims to provide a unified protocol which fits more
 * sophisticated use-cases than a framebuffer device can handle. At the
 * moment basic functionality is supported with the intention to extend:
 * o multiple dynamically allocated/destroyed framebuffers
 * o buffers of arbitrary sizes
 * o better configuration options including multiple display support
 *
 ******************************************************************************
 * Direction of improvements
 ******************************************************************************
 * o allow display/connector cloning
 * o allow allocating objects other than frambeffers
 * o add planes/overlays support
 * o support scaling
 * o support rotation
 */

/*
 * Front->back notifications: When enqueuing a new request, sending a
 * notification can be made conditional on req_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Backends must set
 * req_event appropriately (e.g., using RING_FINAL_CHECK_FOR_REQUESTS()).
 *
 * Back->front notifications: When enqueuing a new response, sending a
 * notification can be made conditional on rsp_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Frontends must set
 * rsp_event appropriately (e.g., using RING_FINAL_CHECK_FOR_RESPONSES()).
 */

/*
 * Feature and Parameter Negotiation
 * =================================
 * The two halves of a para-virtual display driver utilize nodes within the
 * XenStore to communicate capabilities and to negotiate operating parameters.
 * This section enumerates these nodes which reside in the respective front and
 * backend portions of the XenStore, following the XenBus convention.
 *
 * All data in the XenStore is stored as strings.  Nodes specifying numeric
 * values are encoded in decimal.  Integer value ranges listed below are
 * expressed as fixed sized integer types capable of storing the conversion
 * of a properly formated node string, without loss of information.
 *
 *****************************************************************************
 *                            Backend XenBus Nodes
 *****************************************************************************
 *
 *-------------------------------- Addressing ---------------------------------
 *
 * Indices used to address frontends, driver instances,
 * devices and connectors.
 *
 * frontend_id
 *      Values:         <uint>
 *
 *      Domain ID of the display frontend.
 *
 * drv_idx
 *      Values:         <uint>
 *
 *      Zero based contiguous index of the virtualized display driver
 *      instance in this domain. Multiple PV drivers are allowed in the domain
 *      at the same time.
 *
 * conn_id
 *      Values:         <uint>
 *
 *      Zero based contiguous index of the connector within the card.
 *
 *------------------------------ Driver settings -------------------------------
 * features
 *      Values:         <list of strings>
 *
 *      XENDISPL_LIST_SEPARATOR separated list of features that frontend
 *      driver is requested to support. These are not mandatory and may not
 *      be implemented by the frontend:
 *
 *      vblanks
 *             Explicitly request the front driver to emulate vertical blanking
 *             events to the guest OS' software.
 *
 *      be_alloc
 *             Backend can be a buffer provider/allocator during
 *             XENDISPL_OP_DBUF_CREATE operation (see below for negotiation).
 *
 *----------------------------- Connector settings -----------------------------
 * resolution
 *      Values:         <[width]x[height]>
 *
 *      Width and height for the connector in pixels separated by
 *      XENDISPL_RESOLUTION_SEPARATOR. For example,
 *      vdispl/0/connector/0/resolution = "800x600"
 *
 *
 *****************************************************************************
 *                            Frontend XenBus Nodes
 *****************************************************************************
 *
 *----------------------- Request Transport Parameters -----------------------
 *
 * These are per connector.
 *
 * ctrl-channel
 *      Values:         <uint>
 *
 *      The identifier of the Xen connector's control event channel
 *      used to signal activity in the ring buffer.
 *
 * ctrl-ring-ref
 *      Values:         <uint>
 *
 *      The Xen grant reference granting permission for the backend to map
 *      a sole page in a single page sized connector's control ring buffer.
 *
 * event-channel
 *      Values:         <uint>
 *
 *      The identifier of the Xen connector's event channel
 *      used to signal activity in the ring buffer.
 *
 * event-ring-ref
 *      Values:         <uint>
 *
 *      The Xen grant reference granting permission for the backend to map
 *      a sole page in a single page sized connector's event ring buffer.
 */

/*
 * STATE DIAGRAMS
 *
 *****************************************************************************
 *                                   Startup                                 *
 *****************************************************************************
 *
 * Tool stack creates front and back state nodes with initial state
 * XenbusStateInitialising.
 * Tool stack creates and sets up frontend display configuration
 * nodes per domain.
 *
 * Front                                Back
 * =================================    =====================================
 * XenbusStateInitialising              XenbusStateInitialising
 *                                       o Query backend device identification
 *                                         data.
 *                                       o Open and validate backend device.
 *                                                      |
 *                                                      |
 *                                                      V
 *                                      XenbusStateInitWait
 *
 * o Query frontend configuration
 * o Allocate and initialize
 *   event channels and buffers
 * o Publish transport parameters
 *   that will be in effect during
 *   this connection.
 *              |
 *              |
 *              V
 * XenbusStateInitialised
 *
 *                                       o Query frontend transport parameters.
 *                                       o Connect to the event channels.
 *                                                      |
 *                                                      |
 *                                                      V
 *                                      XenbusStateConnected
 *
 *  o Create and initialize OS
 *  virtual DISPL as per configuration.
 *              |
 *              |
 *              V
 * XenbusStateConnected
 *
 *                                      XenbusStateUnknown
 *                                      XenbusStateClosed
 *                                      XenbusStateClosing
 * o Remove virtual display device
 * o Remove event channels
 *              |
 *              |
 *              V
 * XenbusStateClosed
 *
 */

/*
 * REQUEST CODES.
 */
#define XENDISPL_OP_DBUF_CREATE           0
#define XENDISPL_OP_DBUF_DESTROY          1
#define XENDISPL_OP_FB_ATTACH             2
#define XENDISPL_OP_FB_DETACH             3
#define XENDISPL_OP_SET_CONFIG            4
#define XENDISPL_OP_PG_FLIP               5

/*
 * EVENT CODES.
 */
#define XENDISPL_EVT_PG_FLIP              0

/*
 * XENSTORE FIELD AND PATH NAME STRINGS, HELPERS.
 */
#define XENDISPL_DRIVER_NAME              "vdispl"

#define XENDISPL_LIST_SEPARATOR           ";"
#define XENDISPL_RESOLUTION_SEPARATOR     "x"
/* Field names */
#define XENDISPL_FIELD_FEATURES           "features"
#define XENDISPL_FIELD_CTRL_RING_REF      "ctrl-ring-ref"
#define XENDISPL_FIELD_CTRL_CHANNEL       "ctrl-channel"
#define XENDISPL_FIELD_EVT_RING_REF       "event-ring-ref"
#define XENDISPL_FIELD_EVT_CHANNEL        "event-channel"
#define XENDISPL_FIELD_RESOLUTION         "resolution"

#define XENDISPL_FEATURE_VBLANKS           "vblanks"
#define XENDISPL_FEATURE_BE_ALLOC          "be_alloc"

/*
 * STATUS RETURN CODES.
 */
/* Operation parameters are invalid */
#define XENDISPL_RSP_INVAL                (-4)
/* Operation cannot be completed because of memory constraints */
#define XENDISPL_RSP_NOMEM                (-3)
/* Operation is not supported */
#define XENDISPL_RSP_NOTSUPP              (-2)
/* Operation failed for some unspecified reason (e. g. -EIO) */
#define XENDISPL_RSP_ERROR                (-1)
/* Operation completed successfully */
#define XENDISPL_RSP_OKAY                 0

/* Path entries */
#define XENDISPL_PATH_CONNECTOR           "connector"

/*
 * Assumptions:
 *   o usage of grant reference 0 as invalid grant reference:
 *     grant reference 0 is valid, but never exposed to a PV driver,
 *     because of the fact it is already in use/reserved by the PV console.
 *   o all references in this document to page sizes must be treated
 *     as pages of size XEN_PAGE_SIZE (XC_PAGE_SIZE) unless  otherwise noted.
 *
 * Description of the protocol between frontend and backend driver.
 *
 * The two halves of a Para-virtual display driver communicate with
 * each other using a shared page and an event channel.
 * Shared page contains a ring with request/response packets.
 *
 * All reserved fields in the structures below must be 0.
 * Display buffers's cookie of value 0 treated as invalid.
 * Framebuffer's cookie of value 0 treated as invalid.
 *
 * All requests/responses, which are not connector specific, must be sent over
 * control ring of the connector with index 0.
 *
 *****************************************************************************
 *                            Frontend to backend requests
 *****************************************************************************
 *
 * All request packets have the same length (64 octets)
 * All request packets have common header:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |    reserved     |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * id - uint16_t, private guest value, echoed in response
 * operation - uint8_t, operation code
 *
 *
 * Request dbuf creation - request creation of a display buffer.
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | _OP_DBUF_CREATE |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie low 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie high 32-bit                       |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 width                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 height                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                  bpp                                  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               buffer_sz                               |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 flags                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         gref_directory_start                          |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * Must be sent over control ring of the connector with index 0.
 *
 * dbuf_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote display buffer to local in requests
 * width - uint32_t, width in pixels
 * height - uint32_t, height in pixels
 * bpp - uint32_t, bits per pixel
 * buffer_sz - uint32_t, buffer size to be allocated in octets
 * flags - uint32_t, flags of the operation
 *   o XENDISPL_DBUF_FLG_REQ_ALLOC - if set, then backend is requested
 *     to allocate the buffer with the parameters provided in this request.
 *     Page directory is handled as follows:
 *       Frontend on request:
 *         o allocates pages for the directory
 *         o grants permissions for the pages of the directory
 *         o sets gref_dir_next_page fields
 *       Backend on response:
 *         o grants permissions for the pages of the buffer allocated
 *         o fills in page directory with grant references
 * gref_directory_start - grant_ref_t, a reference to the first shared page
 *   describing shared buffer references. At least one page exists. If shared
 *   buffer size exceeds what can be addressed by this single page, then
 *   reference to the next page must be supplied (see gref_dir_next_page below)
 */

#define XENDISPL_DBUF_FLG_REQ_ALLOC       0x0001

struct xendispl_dbuf_create_req {
    uint64_t dbuf_cookie;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t buffer_sz;
    uint32_t flags;
    grant_ref_t gref_directory_start;
};

/*
 * Shared page for XENDISPL_OP_DBUF_CREATE buffer descriptor (gref_directory in
 *   the request) employs a list of pages, describing all pages of the shared
 *   data buffer:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          gref_dir_next_page                           |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[0]                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[i]                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[N-1]                              |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * gref_dir_next_page - grant_ref_t, reference to the next page describing
 *   page directory. Must be 0 if no more pages in the list.
 * gref[i] - grant_ref_t, reference to a shared page of the display buffer
 *   allocated at XENDISPL_OP_DBUF_CREATE
 *
 * Number of grant_ref_t entries in the whole page directory is not
 * passed, but instead can be calculated as:
 *   num_grefs_total = (XENDISPL_OP_DBUF_CREATE.buffer_sz + XEN_PAGE_SIZE - 1) /
 *       XEN_PAGE_SIZE
 */

struct xendispl_page_directory {
    grant_ref_t gref_dir_next_page;
    grant_ref_t gref[1]; /* Variable length */
};

/*
 * Request dbuf destruction - destroy a previously allocated display buffer:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | _OP_DBUF_DESTROY|     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie low 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie high 32-bit                       |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * Must be sent over control ring of the connector with index 0.
 *
 * dbuf_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote display buffer to local in requests
 */

struct xendispl_dbuf_destroy_req {
    uint64_t dbuf_cookie;
};

/*
 * Request framebuffer attachment - request attachment of a framebuffer to
 *   previously created display buffer.
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | _OP_FB_ATTACH   |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie low 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         dbuf_cookie high 32-bit                       |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie low 32-bit                         |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie high 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 width                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 height                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                              pixel_format                             |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * Must be sent over control ring of the connector with index 0.
 *
 * dbuf_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote display buffer to local in requests
 * fb_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote framebuffer to local in requests
 * width - uint32_t, width in pixels
 * height - uint32_t, height in pixels
 * pixel_format - uint32_t, pixel format of the framebuffer, FOURCC code
 */

struct xendispl_fb_attach_req {
    uint64_t dbuf_cookie;
    uint64_t fb_cookie;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
};

/*
 * Request framebuffer detach - detach a previously
 *   attached framebuffer from the display buffer in request:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |  _OP_FB_DETACH  |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie low 32-bit                         |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie high 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * Must be sent over control ring of the connector with index 0.
 *
 * fb_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote framebuffer to local in requests
 */

struct xendispl_fb_detach_req {
    uint64_t fb_cookie;
};

/*
 * Request configuration set/reset - request to set or reset
 *   the configuration/mode of the display:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | _OP_SET_CONFIG  |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie low 32-bit                         |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie high 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                   x                                   |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                   y                                   |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 width                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                 height                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                  bpp                                  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * Pass all zeros to reset, otherwise command is treated as
 * configuration set.
 * If this is a set configuration request then framebuffer's cookie tells
 * the display which framebuffer/dbuf must be shown while enabling display
 * (applying configuration).
 *
 * fb_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote framebuffer to local in requests
 * x - uint32_t, starting position in pixels by X axis
 * y - uint32_t, starting position in pixels by Y axis
 * width - uint32_t, width in pixels
 * height - uint32_t, height in pixels
 * bpp - uint32_t, bits per pixel
 */

struct xendispl_set_config_req {
    uint64_t fb_cookie;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
};

/*
 * Request page flip - request to flip a page identified by the framebuffer
 *   cookie:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | _OP_PG_FLIP     |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie low 32-bit                         |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie high 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * fb_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote framebuffer to local in requests
 */

struct xendispl_page_flip_req {
    uint64_t fb_cookie;
};

/*
 * All response packets have the same length (64 octets)
 *
 * Response for all requests:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |      status     |    reserved     |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * id - uint16_t, private guest value, echoed from request
 * status - int8_t, response status
 */

/*****************************************************************************
 *                            Backend to frontend events
 *****************************************************************************
 *
 * All event packets have the same length (64 octets)
 * Events are sent via a shared page allocated by the front and propagated by
 *   event-channel/event-ring-ref XenStore entries
 *
 * All event packets have common header:
 *
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |      type       |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * id - uint16_t, event id, may be used by front
 * type - uint8_t, type of the event
 *
 *
 * Page flip complete event - event from back to front on page flip completed:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |   _EVT_PG_FLIP  |     reserved    |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie low 32-bit                         |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          fb_cookie high 32-bit                        |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * fb_cookie - uint64_t, unique to guest domain value used by the backend
 *   to map remote framebuffer to local in requests
 *
 */

struct xendispl_pg_flip_evt {
    uint64_t fb_cookie;
};

struct xendispl_req {
    uint16_t id;
    uint8_t operation;
    uint8_t reserved[5];
    union {
        struct xendispl_dbuf_create_req dbuf_create;
        struct xendispl_dbuf_destroy_req dbuf_destroy;
        struct xendispl_fb_attach_req fb_attach;
        struct xendispl_fb_detach_req fb_detach;
        struct xendispl_set_config_req set_config;
        struct xendispl_page_flip_req pg_flip;
        uint8_t reserved[56];
    } op;
};

struct xendispl_resp {
    uint16_t id;
    uint8_t operation;
    int8_t status;
    uint8_t reserved[60];
};

struct xendispl_evt {
    uint16_t id;
    uint8_t type;
    uint8_t reserved[5];
    union {
        struct xendispl_pg_flip_evt pg_flip;
        uint8_t reserved[56];
    } op;
};

DEFINE_RING_TYPES(xen_displif, struct xendispl_req, struct xendispl_resp);

/******************************************************************************
 * Back to front events
 ******************************************************************************
 * In order to deliver asynchronous events from back to front a shared page is
 * allocated by front and its grefs propagated to back via XenStore entries
 * (event-XXX).
 * This page has a common header used by both front and back to synchronize
 * access and control event's ring buffer, while back being a producer of the
 * events and front being a consumer. The rest of the page after the header
 * is used for event packets.
 *
 * Upon reception of an event(s) front may confirm its reception
 * for either each event, group of events or none.
 */

struct xendispl_event_page {
    uint32_t in_cons;
    uint32_t in_prod;
    uint8_t reserved[60];
};

#define XENDISPL_EVENT_PAGE_SIZE 4096
#define XENDISPL_IN_RING_OFFS (sizeof(struct xendispl_event_page))
#define XENDISPL_IN_RING_SIZE (XENDISPL_EVENT_PAGE_SIZE - XENDISPL_IN_RING_OFFS)
#define XENDISPL_IN_RING_LEN (XENDISPL_IN_RING_SIZE / sizeof(struct xendispl_evt))
#define XENDISPL_IN_RING(page) \
	((struct xendispl_evt *)((char *)(page) + XENDISPL_IN_RING_OFFS))
#define XENDISPL_IN_RING_REF(page, idx) \
	(XENDISPL_IN_RING((page))[(idx) % XENDISPL_IN_RING_LEN])

#endif /* __XEN_PUBLIC_IO_DISPLIF_H__ */
