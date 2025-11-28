/**
 * collectd - src/netlink.c
 * Copyright (C) 2007-2010  Florian octo Forster
 * Copyright (C) 2008-2012  Sebastian Harl
 * Copyright (C) 2013       Andreas Henriksson
 * Copyright (C) 2013       Marc Fournier
 * Copyright (C) 2020       Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 *   Sebastian Harl <sh at tokkee.org>
 *   Andreas Henriksson <andreas at fatal.se>
 *   Marc Fournier <marc.fournier at camptocamp.com>
 *   Kamil Wiatrowski <kamilx.wiatrowski at intel.com>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#if HAVE_REGEX_H
#include <regex.h>
#endif

#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#if HAVE_LINUX_GEN_STATS_H
#include <linux/gen_stats.h>
#endif
#if HAVE_LINUX_PKT_SCHED_H
#include <linux/pkt_sched.h>
#endif

#include <glob.h>
#include <libmnl/libmnl.h>

#define NETLINK_VF_DEFAULT_BUF_SIZE_KB 16

struct ir_link_stats_storage_s {

  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
  uint64_t rx_errors;
  uint64_t tx_errors;

  uint64_t rx_dropped;
  uint64_t tx_dropped;
  uint64_t multicast;
  uint64_t collisions;
  uint64_t rx_nohandler;

  uint64_t rx_length_errors;
  uint64_t rx_over_errors;
  uint64_t rx_crc_errors;
  uint64_t rx_frame_errors;
  uint64_t rx_fifo_errors;
  uint64_t rx_missed_errors;

  uint64_t tx_aborted_errors;
  uint64_t tx_carrier_errors;
  uint64_t tx_fifo_errors;
  uint64_t tx_heartbeat_errors;
  uint64_t tx_window_errors;
};

union ir_link_stats_u {
  struct rtnl_link_stats *stats32;
#ifdef HAVE_RTNL_LINK_STATS64
  struct rtnl_link_stats64 *stats64;
#endif
};

#ifdef HAVE_IFLA_VF_STATS
typedef struct vf_stats_s {
  struct ifla_vf_mac *vf_mac;
  uint32_t vlan;
  uint32_t qos;
  uint32_t spoofcheck;
  uint32_t link_state;
  uint32_t txrate;
  uint32_t min_txrate;
  uint32_t max_txrate;
  uint32_t rss_query_en;
  uint32_t trust;

  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
  uint64_t broadcast;
  uint64_t multicast;
#ifdef HAVE_IFLA_VF_STATS_RX_DROPPED
  uint64_t rx_dropped;
#endif
#ifdef HAVE_IFLA_VF_STATS_TX_DROPPED
  uint64_t tx_dropped;
#endif
} vf_stats_t;
#endif

typedef struct ir_ignorelist_s {
  char *device;
#if HAVE_REGEX_H
  regex_t *rdevice; /* regular expression device identification */
#endif
  char *type;
  char *inst;
  struct ir_ignorelist_s *next;
} ir_ignorelist_t;

struct qos_stats {
  struct gnet_stats_basic *bs;
  struct gnet_stats_queue *qs;
  struct nlattr *xstats;  /* Extended stats (TCA_STATS_APP) for qdisc-specific data */
};

static int ir_ignorelist_invert = 1;
static ir_ignorelist_t *ir_ignorelist_head;

static struct mnl_socket *nl;

static char **iflist;
static size_t iflist_len;

static bool collect_vf_stats = false;
static size_t nl_socket_buffer_size = NETLINK_VF_DEFAULT_BUF_SIZE_KB * 1024;
static char *read_buffer = NULL;

static const char *config_keys[] = {
    "Interface", "VerboseInterface", "QDisc",         "Class",
    "Filter",    "IgnoreSelected",   "CollectVFStats"};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static int add_ignorelist(const char *dev, const char *type, const char *inst) {
  ir_ignorelist_t *entry;

  entry = calloc(1, sizeof(*entry));
  if (entry == NULL)
    return -1;

#if HAVE_REGEX_H
  size_t len = strlen(dev);
  /* regex string is enclosed in "/.../" */
  if ((len > 2) && (dev[0] == '/') && dev[len - 1] == '/') {
    char *copy = strdup(dev + 1);
    if (copy == NULL) {
      sfree(entry);
      return -1;
    }
    copy[strlen(copy) - 1] = '\0';

    regex_t *re = calloc(1, sizeof(*re));
    if (re == NULL) {
      sfree(entry);
      sfree(copy);
      return -1;
    }

    int status = regcomp(re, copy, REG_EXTENDED);
    if (status != 0) {
      char errbuf[1024];
      (void)regerror(status, re, errbuf, sizeof(errbuf));
      ERROR("netlink plugin: add_ignorelist: regcomp for %s failed: %s", dev,
            errbuf);
      sfree(entry);
      sfree(copy);
      sfree(re);
      return -1;
    }

    entry->rdevice = re;
    sfree(copy);
  } else
#endif
      if (strcasecmp(dev, "All") != 0) {
    entry->device = strdup(dev);
    if (entry->device == NULL) {
      sfree(entry);
      return -1;
    }
  }

  entry->type = strdup(type);
  if (entry->type == NULL) {
    sfree(entry->device);
#if HAVE_REGEX_H
    if (entry->rdevice != NULL) {
      regfree(entry->rdevice);
      sfree(entry->rdevice);
    }
#endif
    sfree(entry);
    return -1;
  }

  if (inst != NULL) {
    entry->inst = strdup(inst);
    if (entry->inst == NULL) {
      sfree(entry->type);
      sfree(entry->device);
#if HAVE_REGEX_H
      if (entry->rdevice != NULL) {
        regfree(entry->rdevice);
        sfree(entry->rdevice);
      }
#endif
      sfree(entry);
      return -1;
    }
  }

  entry->next = ir_ignorelist_head;
  ir_ignorelist_head = entry;

  return 0;
} /* int add_ignorelist */

/*
 * Checks wether a data set should be ignored. Returns `true' is the value
 * should be ignored, `false' otherwise.
 */
static int check_ignorelist(const char *dev, const char *type,
                            const char *type_instance) {
  assert((dev != NULL) && (type != NULL));

  if (ir_ignorelist_head == NULL)
    return ir_ignorelist_invert ? 0 : 1;

  for (ir_ignorelist_t *i = ir_ignorelist_head; i != NULL; i = i->next) {
#if HAVE_REGEX_H
    if (i->rdevice != NULL) {
      if (regexec(i->rdevice, dev, 0, NULL, 0) != REG_NOERROR)
        continue;
    } else
#endif
        /* i->device == NULL  =>  match all devices */
        if ((i->device != NULL) && (strcasecmp(i->device, dev) != 0))
      continue;

    if (strcasecmp(i->type, type) != 0)
      continue;

    if ((i->inst != NULL) && (type_instance != NULL) &&
        (strcasecmp(i->inst, type_instance) != 0))
      continue;

#if COLLECT_DEBUG
#if HAVE_REGEX_H
    const char *device = i->device == NULL
                             ? (i->rdevice != NULL ? "(regexp)" : "(nil)")
                             : i->device;
#else
    const char *device = i->device == NULL ? "(nil)" : i->device;
#endif
    DEBUG("netlink plugin: check_ignorelist: "
          "(dev = %s; type = %s; inst = %s) matched "
          "(dev = %s; type = %s; inst = %s)",
          dev, type, type_instance == NULL ? "(nil)" : type_instance, device,
          i->type, i->inst == NULL ? "(nil)" : i->inst);
#endif

    return ir_ignorelist_invert ? 0 : 1;
  } /* for i */

  return ir_ignorelist_invert;
} /* int check_ignorelist */

#ifdef HAVE_IFLA_VF_STATS
static void submit_one_gauge(const char *dev, const char *type,
                             const char *type_instance, gauge_t value) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = &(value_t){.gauge = value};
  vl.values_len = 1;
  sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
} /* void submit_one_gauge */
#endif

static void submit_one(const char *dev, const char *type,
                       const char *type_instance, derive_t value) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = &(value_t){.derive = value};
  vl.values_len = 1;
  sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
} /* void submit_one */

static void submit_two(const char *dev, const char *type,
                       const char *type_instance, derive_t rx, derive_t tx) {
  value_list_t vl = VALUE_LIST_INIT;
  value_t values[] = {
      {.derive = rx},
      {.derive = tx},
  };

  vl.values = values;
  vl.values_len = STATIC_ARRAY_SIZE(values);
  sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
} /* void submit_two */

/* Submit CAKE tin statistics - aligned with HTB format */
static int submit_cake_tin(const char *dev, const char *tc_inst, int tin_idx,
                            const char *type, const char *suffix, derive_t value) {
  value_list_t vl = VALUE_LIST_INIT;
  value_t values[1];
  char type_instance[DATA_MAX_NAME_LEN];
  char plugin_instance[DATA_MAX_NAME_LEN];

  values[0].derive = value;

  vl.values = values;
  vl.values_len = 1;
  sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));

  /* Include TIN index in plugin_instance for proper TDengine filtering */
  int pi_status = ssnprintf(plugin_instance, sizeof(plugin_instance),
                            "%s_tin%d", dev, tin_idx);
  if (pi_status >= sizeof(plugin_instance)) {
    ERROR("netlink plugin: CAKE plugin_instance name truncated");
    return -1;
  }
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));

  sstrncpy(vl.type, type, sizeof(vl.type));

  /* Format type_instance: "cake-4:0" or "peak-cake-4:0" */
  int status;
  if (suffix != NULL && suffix[0] != '\0') {
    status = ssnprintf(type_instance, sizeof(type_instance),
                       "%s-%s", suffix, tc_inst);
  } else {
    status = ssnprintf(type_instance, sizeof(type_instance),
                       "%s", tc_inst);
  }

  if (status >= sizeof(type_instance)) {
    ERROR("netlink plugin: CAKE tin instance name truncated");
    return -1;
  }

  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  return plugin_dispatch_values(&vl);
}

/* Submit CAKE tin statistics as gauge - aligned with HTB format */
static int submit_cake_tin_gauge(const char *dev, const char *tc_inst, int tin_idx,
                                  const char *type, const char *suffix,
                                  gauge_t value) {
  value_list_t vl = VALUE_LIST_INIT;
  value_t values[1];
  char type_instance[DATA_MAX_NAME_LEN];
  char plugin_instance[DATA_MAX_NAME_LEN];

  values[0].gauge = value;

  vl.values = values;
  vl.values_len = 1;
  sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));

  /* Include TIN index in plugin_instance for proper TDengine filtering */
  int pi_status = ssnprintf(plugin_instance, sizeof(plugin_instance),
                            "%s_tin%d", dev, tin_idx);
  if (pi_status >= sizeof(plugin_instance)) {
    ERROR("netlink plugin: CAKE plugin_instance gauge name truncated");
    return -1;
  }
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));

  sstrncpy(vl.type, type, sizeof(vl.type));

  /* Format type_instance: "peak-cake-4:0" */
  int status;
  if (suffix != NULL && suffix[0] != '\0') {
    status = ssnprintf(type_instance, sizeof(type_instance),
                       "%s-%s", suffix, tc_inst);
  } else {
    status = ssnprintf(type_instance, sizeof(type_instance),
                       "%s", tc_inst);
  }

  if (status >= sizeof(type_instance)) {
    ERROR("netlink plugin: CAKE tin gauge instance name truncated");
    return -1;
  }

  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  return plugin_dispatch_values(&vl);
}

static int update_iflist(struct ifinfomsg *msg, const char *dev) {
  /* Update the `iflist'. It's used to know which interfaces exist and query
   * them later for qdiscs and classes. */
  if ((msg->ifi_index >= 0) && ((size_t)msg->ifi_index >= iflist_len)) {
    char **temp;

    temp = realloc(iflist, (msg->ifi_index + 1) * sizeof(char *));
    if (temp == NULL) {
      ERROR("netlink plugin: update_iflist: realloc failed.");
      return -1;
    }

    memset(temp + iflist_len, '\0',
           (msg->ifi_index + 1 - iflist_len) * sizeof(char *));
    iflist = temp;
    iflist_len = msg->ifi_index + 1;
  }
  if ((iflist[msg->ifi_index] == NULL) ||
      (strcmp(iflist[msg->ifi_index], dev) != 0)) {
    sfree(iflist[msg->ifi_index]);
    iflist[msg->ifi_index] = strdup(dev);
    if (iflist[msg->ifi_index] == NULL) {
      ERROR("netlink plugin: update_iflist: strdup failed.");
      return -1;
    }
  }

  return 0;
} /* int update_iflist */

static void check_ignorelist_and_submit(const char *dev,
                                        struct ir_link_stats_storage_s *stats) {

  if (check_ignorelist(dev, "interface", NULL) == 0) {
    submit_two(dev, "if_octets", NULL, stats->rx_bytes, stats->tx_bytes);
    submit_two(dev, "if_packets", NULL, stats->rx_packets, stats->tx_packets);
    submit_two(dev, "if_errors", NULL, stats->rx_errors, stats->tx_errors);
  } else {
    DEBUG("netlink plugin: Ignoring %s/interface.", dev);
  }

  if (check_ignorelist(dev, "if_detail", NULL) == 0) {
    submit_two(dev, "if_dropped", NULL, stats->rx_dropped, stats->tx_dropped);
    submit_one(dev, "if_multicast", NULL, stats->multicast);
    submit_one(dev, "if_collisions", NULL, stats->collisions);
#if defined(HAVE_STRUCT_RTNL_LINK_STATS_RX_NOHANDLER) ||                       \
    defined(HAVE_STRUCT_RTNL_LINK_STATS64_RX_NOHANDLER)
    submit_one(dev, "if_rx_nohandler", NULL, stats->rx_nohandler);
#endif

    submit_one(dev, "if_rx_errors", "length", stats->rx_length_errors);
    submit_one(dev, "if_rx_errors", "over", stats->rx_over_errors);
    submit_one(dev, "if_rx_errors", "crc", stats->rx_crc_errors);
    submit_one(dev, "if_rx_errors", "frame", stats->rx_frame_errors);
    submit_one(dev, "if_rx_errors", "fifo", stats->rx_fifo_errors);
    submit_one(dev, "if_rx_errors", "missed", stats->rx_missed_errors);

    submit_one(dev, "if_tx_errors", "aborted", stats->tx_aborted_errors);
    submit_one(dev, "if_tx_errors", "carrier", stats->tx_carrier_errors);
    submit_one(dev, "if_tx_errors", "fifo", stats->tx_fifo_errors);
    submit_one(dev, "if_tx_errors", "heartbeat", stats->tx_heartbeat_errors);
    submit_one(dev, "if_tx_errors", "window", stats->tx_window_errors);
  } else {
    DEBUG("netlink plugin: Ignoring %s/if_detail.", dev);
  }

} /* void check_ignorelist_and_submit */

#define COPY_RTNL_LINK_VALUE(dst_stats, src_stats, value_name)                 \
  (dst_stats)->value_name = (src_stats)->value_name

#define COPY_RTNL_LINK_STATS(dst_stats, src_stats)                             \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_packets);                      \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_packets);                      \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_bytes);                        \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_bytes);                        \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_errors);                       \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_errors);                       \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_dropped);                      \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_dropped);                      \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, multicast);                       \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, collisions);                      \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_length_errors);                \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_over_errors);                  \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_crc_errors);                   \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_frame_errors);                 \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_fifo_errors);                  \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, rx_missed_errors);                \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_aborted_errors);               \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_carrier_errors);               \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_fifo_errors);                  \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_heartbeat_errors);             \
  COPY_RTNL_LINK_VALUE(dst_stats, src_stats, tx_window_errors)

#ifdef HAVE_RTNL_LINK_STATS64
static void check_ignorelist_and_submit64(const char *dev,
                                          struct rtnl_link_stats64 *stats) {
  struct ir_link_stats_storage_s s;

  COPY_RTNL_LINK_STATS(&s, stats);
#ifdef HAVE_STRUCT_RTNL_LINK_STATS64_RX_NOHANDLER
  COPY_RTNL_LINK_VALUE(&s, stats, rx_nohandler);
#endif

  check_ignorelist_and_submit(dev, &s);
}
#endif

static void check_ignorelist_and_submit32(const char *dev,
                                          struct rtnl_link_stats *stats) {
  struct ir_link_stats_storage_s s;

  COPY_RTNL_LINK_STATS(&s, stats);
#ifdef HAVE_STRUCT_RTNL_LINK_STATS_RX_NOHANDLER
  COPY_RTNL_LINK_VALUE(&s, stats, rx_nohandler);
#endif

  check_ignorelist_and_submit(dev, &s);
}

#ifdef HAVE_IFLA_VF_STATS
static void vf_info_submit(const char *dev, vf_stats_t *vf_stats) {
  if (vf_stats->vf_mac == NULL) {
    ERROR("netlink plugin: vf_info_submit: failed to get VF macaddress, "
          "skipping VF for interface %s",
          dev);
    return;
  }
  uint8_t *mac = vf_stats->vf_mac->mac;
  uint32_t vf_num = vf_stats->vf_mac->vf;
  char instance[512];
  int status =
      ssnprintf(instance, sizeof(instance), "%s_vf%u_%02x:%02x:%02x:%02x:%02x:%02x",
                dev, vf_num, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  if (status < 0 || (size_t)status >= sizeof(instance)) {
    ERROR("netlink plugin: vf_info_submit: ssnprintf failed or truncated.");
    return;
  }
  DEBUG("netlink plugin: vf_info_submit: plugin_instance - %s", instance);

  submit_one_gauge(instance, "vf_link_info", "number", vf_num);
  submit_one_gauge(instance, "vf_link_info", "vlan", vf_stats->vlan);
  submit_one_gauge(instance, "vf_link_info", "qos", vf_stats->qos);
  submit_one_gauge(instance, "vf_link_info", "spoofcheck",
                   vf_stats->spoofcheck);
  submit_one_gauge(instance, "vf_link_info", "link_state",
                   vf_stats->link_state);
  submit_one_gauge(instance, "vf_link_info", "tx_rate", vf_stats->txrate);
  submit_one_gauge(instance, "vf_link_info", "min_tx_rate",
                   vf_stats->min_txrate);
  submit_one_gauge(instance, "vf_link_info", "max_tx_rate",
                   vf_stats->max_txrate);
  submit_one_gauge(instance, "vf_link_info", "rss_query_en",
                   vf_stats->rss_query_en);
  submit_one_gauge(instance, "vf_link_info", "trust", vf_stats->trust);

  submit_one(instance, "vf_broadcast", NULL, vf_stats->broadcast);
  submit_one(instance, "vf_multicast", NULL, vf_stats->multicast);
  submit_two(instance, "vf_packets", NULL, vf_stats->rx_packets,
             vf_stats->tx_packets);
  submit_two(instance, "vf_bytes", NULL, vf_stats->rx_bytes,
             vf_stats->tx_bytes);
#if defined(HAVE_IFLA_VF_STATS_RX_DROPPED) &&                                  \
    defined(HAVE_IFLA_VF_STATS_TX_DROPPED)
  submit_two(instance, "vf_dropped", NULL, vf_stats->rx_dropped,
             vf_stats->tx_dropped);
#endif
} /* void vf_info_submit */

#define IFCOPY_VF_STAT_VALUE(attr, name, type_name)                            \
  do {                                                                         \
    if (mnl_attr_get_type(attr) == type_name) {                                \
      if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {                         \
        ERROR("netlink plugin: vf_info_attr_cb: " #type_name                   \
              " mnl_attr_validate failed.");                                   \
        return MNL_CB_ERROR;                                                   \
      }                                                                        \
      vf_stats->name = mnl_attr_get_u64(attr);                                 \
    }                                                                          \
  } while (0)

static int vf_info_attr_cb(const struct nlattr *attr, void *args) {
  vf_stats_t *vf_stats = (vf_stats_t *)args;

  /* skip unsupported attribute */
  if (mnl_attr_type_valid(attr, IFLA_VF_MAX) < 0) {
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_MAC) {
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_stats->vf_mac)) <
        0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_MAC mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_stats->vf_mac = (struct ifla_vf_mac *)mnl_attr_get_payload(attr);
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_VLAN) {
    struct ifla_vf_vlan *vf_vlan;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_vlan)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_VLAN mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_vlan = (struct ifla_vf_vlan *)mnl_attr_get_payload(attr);
    vf_stats->vlan = vf_vlan->vlan;
    vf_stats->qos = vf_vlan->qos;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_TX_RATE) {
    struct ifla_vf_tx_rate *vf_txrate;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_txrate)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_TX_RATE "
            "mnl_attr_validate2 failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_txrate = (struct ifla_vf_tx_rate *)mnl_attr_get_payload(attr);
    vf_stats->txrate = vf_txrate->rate;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_SPOOFCHK) {
    struct ifla_vf_spoofchk *vf_spoofchk;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_spoofchk)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_SPOOFCHK "
            "mnl_attr_validate2 failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_spoofchk = (struct ifla_vf_spoofchk *)mnl_attr_get_payload(attr);
    vf_stats->spoofcheck = vf_spoofchk->setting;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_LINK_STATE) {
    struct ifla_vf_link_state *vf_link_state;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_link_state)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_LINK_STATE "
            "mnl_attr_validate2 failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_link_state = (struct ifla_vf_link_state *)mnl_attr_get_payload(attr);
    vf_stats->link_state = vf_link_state->link_state;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_RATE) {
    struct ifla_vf_rate *vf_rate;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_rate)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_RATE mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_rate = (struct ifla_vf_rate *)mnl_attr_get_payload(attr);
    vf_stats->min_txrate = vf_rate->min_tx_rate;
    vf_stats->max_txrate = vf_rate->max_tx_rate;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_RSS_QUERY_EN) {
    struct ifla_vf_rss_query_en *vf_rss_query_en;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_rss_query_en)) <
        0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_RSS_QUERY_EN "
            "mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_rss_query_en = (struct ifla_vf_rss_query_en *)mnl_attr_get_payload(attr);
    vf_stats->rss_query_en = vf_rss_query_en->setting;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_TRUST) {
    struct ifla_vf_trust *vf_trust;
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*vf_trust)) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_TRUST mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }

    vf_trust = (struct ifla_vf_trust *)mnl_attr_get_payload(attr);
    vf_stats->trust = vf_trust->setting;
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == IFLA_VF_STATS) {
    if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
      ERROR("netlink plugin: vf_info_attr_cb: IFLA_VF_STATS mnl_attr_validate "
            "failed.");
      return MNL_CB_ERROR;
    }

    struct nlattr *nested;
    mnl_attr_for_each_nested(nested, attr) {
      IFCOPY_VF_STAT_VALUE(nested, rx_packets, IFLA_VF_STATS_RX_PACKETS);
      IFCOPY_VF_STAT_VALUE(nested, tx_packets, IFLA_VF_STATS_TX_PACKETS);
      IFCOPY_VF_STAT_VALUE(nested, rx_bytes, IFLA_VF_STATS_RX_BYTES);
      IFCOPY_VF_STAT_VALUE(nested, tx_bytes, IFLA_VF_STATS_TX_BYTES);
      IFCOPY_VF_STAT_VALUE(nested, broadcast, IFLA_VF_STATS_BROADCAST);
      IFCOPY_VF_STAT_VALUE(nested, multicast, IFLA_VF_STATS_MULTICAST);
#ifdef HAVE_IFLA_VF_STATS_RX_DROPPED
      IFCOPY_VF_STAT_VALUE(nested, rx_dropped, IFLA_VF_STATS_RX_DROPPED);
#endif
#ifdef HAVE_IFLA_VF_STATS_TX_DROPPED
      IFCOPY_VF_STAT_VALUE(nested, tx_dropped, IFLA_VF_STATS_TX_DROPPED);
#endif
    }
    return MNL_CB_OK;
  }

  return MNL_CB_OK;
} /* int vf_info_attr_cb */
#endif /* HAVE_IFLA_VF_STATS */

static int link_filter_cb(const struct nlmsghdr *nlh,
                          void *args __attribute__((unused))) {
  struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
  struct nlattr *attr;
  const char *dev = NULL;
  union ir_link_stats_u stats;
#ifdef HAVE_IFLA_VF_STATS
  uint32_t num_vfs = 0;
#endif
  bool stats_done = false;

  if (nlh->nlmsg_type != RTM_NEWLINK) {
    ERROR("netlink plugin: link_filter_cb: Don't know how to handle type %i.",
          nlh->nlmsg_type);
    return MNL_CB_ERROR;
  }

  /* Scan attribute list for device name. */
  mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
    if (mnl_attr_get_type(attr) != IFLA_IFNAME)
      continue;

    if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
      ERROR("netlink plugin: link_filter_cb: IFLA_IFNAME mnl_attr_validate "
            "failed.");
      return MNL_CB_ERROR;
    }

    dev = mnl_attr_get_str(attr);
    if (update_iflist(ifm, dev) < 0)
      return MNL_CB_ERROR;
    break;
  }

  if (dev == NULL) {
    ERROR("netlink plugin: link_filter_cb: dev == NULL");
    return MNL_CB_ERROR;
  }

  if (check_ignorelist(dev, "interface", NULL) != 0 &&
      check_ignorelist(dev, "if_detail", NULL) != 0) {
    DEBUG("netlink plugin: link_filter_cb: Ignoring %s/interface.", dev);
    DEBUG("netlink plugin: link_filter_cb: Ignoring %s/if_detail.", dev);
    return MNL_CB_OK;
  }

#ifdef HAVE_IFLA_VF_STATS
  if (collect_vf_stats) {
    mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
      if (mnl_attr_get_type(attr) != IFLA_NUM_VF)
        continue;

      if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
        ERROR("netlink plugin: link_filter_cb: IFLA_NUM_VF mnl_attr_validate "
              "failed.");
        return MNL_CB_ERROR;
      }

      num_vfs = mnl_attr_get_u32(attr);
      break;
    }
  }
#endif

#ifdef HAVE_RTNL_LINK_STATS64
  mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
    if (mnl_attr_get_type(attr) != IFLA_STATS64)
      continue;

    uint16_t attr_len = mnl_attr_get_payload_len(attr);
    if (attr_len < sizeof(*stats.stats64)) {
      ERROR("netlink plugin: link_filter_cb: IFLA_STATS64 attribute has "
            "insufficient data.");
      return MNL_CB_ERROR;
    }
    stats.stats64 = mnl_attr_get_payload(attr);

    check_ignorelist_and_submit64(dev, stats.stats64);

    stats_done = true;
    break;
  }
#endif
  if (stats_done == false) {
    mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
      if (mnl_attr_get_type(attr) != IFLA_STATS)
        continue;

      uint16_t attr_len = mnl_attr_get_payload_len(attr);
      if (attr_len < sizeof(*stats.stats32)) {
        ERROR("netlink plugin: link_filter_cb: IFLA_STATS attribute has "
              "insufficient data.");
        return MNL_CB_ERROR;
      }
      stats.stats32 = mnl_attr_get_payload(attr);

      check_ignorelist_and_submit32(dev, stats.stats32);

      stats_done = true;
      break;
    }
  }

#if COLLECT_DEBUG
  if (stats_done == false)
    DEBUG("netlink plugin: link_filter: No statistics for interface %s.", dev);
#endif

#ifdef HAVE_IFLA_VF_STATS
  if (num_vfs == 0)
    return MNL_CB_OK;

  /* Get VFINFO list. */
  mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
    if (mnl_attr_get_type(attr) != IFLA_VFINFO_LIST)
      continue;

    if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
      ERROR("netlink plugin: link_filter_cb: IFLA_VFINFO_LIST "
            "mnl_attr_validate failed.");
      return MNL_CB_ERROR;
    }

    struct nlattr *nested;
    mnl_attr_for_each_nested(nested, attr) {
      if (mnl_attr_get_type(nested) != IFLA_VF_INFO) {
        continue;
      }

      if (mnl_attr_validate(nested, MNL_TYPE_NESTED) < 0) {
        ERROR("netlink plugin: link_filter_cb: IFLA_VF_INFO mnl_attr_validate "
              "failed.");
        return MNL_CB_ERROR;
      }

      vf_stats_t vf_stats = {0};
      if (mnl_attr_parse_nested(nested, vf_info_attr_cb, &vf_stats) ==
          MNL_CB_ERROR)
        return MNL_CB_ERROR;

      vf_info_submit(dev, &vf_stats);
    }
    break;
  }
#endif

  return MNL_CB_OK;
} /* int link_filter_cb */

#if HAVE_TCA_STATS2
static int qos_attr_cb(const struct nlattr *attr, void *data) {
  struct qos_stats *q_stats = (struct qos_stats *)data;

  /* skip unsupported attribute in user-space */
  if (mnl_attr_type_valid(attr, TCA_STATS_MAX) < 0)
    return MNL_CB_OK;

  if (mnl_attr_get_type(attr) == TCA_STATS_BASIC) {
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*q_stats->bs)) < 0) {
      ERROR("netlink plugin: qos_attr_cb: TCA_STATS_BASIC mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }
    q_stats->bs = mnl_attr_get_payload(attr);
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == TCA_STATS_QUEUE) {
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*q_stats->qs)) < 0) {
      ERROR("netlink plugin: qos_attr_cb: TCA_STATS_QUEUE mnl_attr_validate2 "
            "failed.");
      return MNL_CB_ERROR;
    }
    q_stats->qs = mnl_attr_get_payload(attr);
    return MNL_CB_OK;
  }

  if (mnl_attr_get_type(attr) == TCA_STATS_APP) {
    /* Extended stats for qdisc-specific data (e.g., CAKE tin stats) */
    DEBUG("netlink plugin: Found TCA_STATS_APP attribute");
    if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
      ERROR("netlink plugin: qos_attr_cb: TCA_STATS_APP mnl_attr_validate "
            "failed.");
      return MNL_CB_ERROR;
    }
    q_stats->xstats = (struct nlattr *)attr;
    return MNL_CB_OK;
  }

  /* Debug: log all attributes we receive */
  DEBUG("netlink plugin: qos_attr_cb received attribute type: %d",
        mnl_attr_get_type(attr));

  return MNL_CB_OK;
} /* qos_attr_cb */
#endif

static int qos_filter_cb(const struct nlmsghdr *nlh, void *args) {
  struct tcmsg *tm = mnl_nlmsg_get_payload(nlh);
  struct nlattr *attr;

  int wanted_ifindex = *((int *)args);

  const char *dev;
  const char *kind = NULL;

  /* char *type_instance; */
  const char *tc_type;
  char tc_inst[DATA_MAX_NAME_LEN];

  bool stats_submitted = false;

  if (nlh->nlmsg_type == RTM_NEWQDISC)
    tc_type = "qdisc";
  else if (nlh->nlmsg_type == RTM_NEWTCLASS)
    tc_type = "class";
  else if (nlh->nlmsg_type == RTM_NEWTFILTER)
    tc_type = "filter";
  else {
    ERROR("netlink plugin: qos_filter_cb: Don't know how to handle type %i.",
          nlh->nlmsg_type);
    return MNL_CB_ERROR;
  }

  if (tm->tcm_ifindex != wanted_ifindex) {
    DEBUG("netlink plugin: qos_filter_cb: Got %s for interface #%i, "
          "but expected #%i.",
          tc_type, tm->tcm_ifindex, wanted_ifindex);
    return MNL_CB_OK;
  }

  if ((tm->tcm_ifindex >= 0) && ((size_t)tm->tcm_ifindex >= iflist_len)) {
    ERROR("netlink plugin: qos_filter_cb: tm->tcm_ifindex = %i "
          ">= iflist_len = %" PRIsz,
          tm->tcm_ifindex, iflist_len);
    return MNL_CB_ERROR;
  }

  dev = iflist[tm->tcm_ifindex];
  if (dev == NULL) {
    ERROR("netlink plugin: qos_filter_cb: iflist[%i] == NULL", tm->tcm_ifindex);
    return MNL_CB_ERROR;
  }

  mnl_attr_for_each(attr, nlh, sizeof(*tm)) {
    if (mnl_attr_get_type(attr) != TCA_KIND)
      continue;

    if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
      ERROR(
          "netlink plugin: qos_filter_cb: TCA_KIND mnl_attr_validate failed.");
      return MNL_CB_ERROR;
    }

    kind = mnl_attr_get_str(attr);
    break;
  }

  if (kind == NULL) {
    ERROR("netlink plugin: qos_filter_cb: kind == NULL");
    return MNL_CB_ERROR;
  }

  { /* The ID */
    uint32_t numberic_id;

    numberic_id = tm->tcm_handle;
    if (strcmp(tc_type, "filter") == 0)
      numberic_id = tm->tcm_parent;

    int status = ssnprintf(tc_inst, sizeof(tc_inst), "%s-%x:%x", kind,
                           numberic_id >> 16, numberic_id & 0x0000FFFF);
    if (status < 0 || (size_t)status >= sizeof(tc_inst)) {
      ERROR("netlink plugin: qos_filter_cb: ssnprintf failed or truncated.");
      return MNL_CB_ERROR;
    }
  }

  DEBUG("netlink plugin: qos_filter_cb: got %s for %s (%i).", tc_type, dev,
        tm->tcm_ifindex);

  if (check_ignorelist(dev, tc_type, tc_inst))
    return MNL_CB_OK;

#if HAVE_TCA_STATS2
  mnl_attr_for_each(attr, nlh, sizeof(*tm)) {
    struct qos_stats q_stats;

    memset(&q_stats, 0x0, sizeof(q_stats));

    if (mnl_attr_get_type(attr) != TCA_STATS2)
      continue;

    if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
      ERROR("netlink plugin: qos_filter_cb: TCA_STATS2 mnl_attr_validate "
            "failed.");
      return MNL_CB_ERROR;
    }

    DEBUG("netlink plugin: Parsing TCA_STATS2 for %s (kind=%s)", dev, kind);
    mnl_attr_parse_nested(attr, qos_attr_cb, &q_stats);

    DEBUG("netlink plugin: After parsing: bs=%p, qs=%p, xstats=%p",
          q_stats.bs, q_stats.qs, q_stats.xstats);

    if (q_stats.bs != NULL || q_stats.qs != NULL) {
      char type_instance[DATA_MAX_NAME_LEN];

      stats_submitted = true;

      int r = ssnprintf(type_instance, sizeof(type_instance), "%s-%s", tc_type,
                        tc_inst);
      if ((size_t)r >= sizeof(type_instance)) {
        ERROR("netlink plugin: type_instance truncated to %zu bytes, need %d",
              sizeof(type_instance), r);
        return MNL_CB_ERROR;
      }

      if (q_stats.bs != NULL) {
        submit_one(dev, "ipt_bytes", type_instance, q_stats.bs->bytes);
        submit_one(dev, "ipt_packets", type_instance, q_stats.bs->packets);
      }
      if (q_stats.qs != NULL) {
        submit_one(dev, "if_tx_dropped", type_instance, q_stats.qs->drops);
        /* Submit overlimits for HTB/CBQ classes - important for bandwidth monitoring */
        /* Always submit overlimits metric, even when zero, for consistent monitoring */
        char overlimit_inst[DATA_MAX_NAME_LEN];
        int status = ssnprintf(overlimit_inst, sizeof(overlimit_inst), "%s-overlimits", type_instance);
        if (status >= sizeof(overlimit_inst)) {
          WARNING("netlink plugin: Instance name too long for overlimits metric, "
                  "truncated: %s-overlimits", type_instance);
        }
        submit_one(dev, "derive", overlimit_inst, q_stats.qs->overlimits);
      }

      /* Process CAKE extended stats (tin statistics) from TCA_STATS_APP */
      if (q_stats.xstats != NULL && kind != NULL && strcmp(kind, "cake") == 0) {
        struct nlattr *cake_attr;
        struct nlattr *tin_stats_attr = NULL;
        uint64_t capacity_estimate = 0;
        uint32_t memory_used = 0, memory_limit = 0;

        /* Parse CAKE global statistics from TCA_STATS_APP */
        mnl_attr_for_each_nested(cake_attr, q_stats.xstats) {
          int type = mnl_attr_get_type(cake_attr);

          if (type == TCA_CAKE_STATS_MEMORY_USED &&
              mnl_attr_validate(cake_attr, MNL_TYPE_U32) >= 0) {
            memory_used = mnl_attr_get_u32(cake_attr);
          } else if (type == TCA_CAKE_STATS_MEMORY_LIMIT &&
                     mnl_attr_validate(cake_attr, MNL_TYPE_U32) >= 0) {
            memory_limit = mnl_attr_get_u32(cake_attr);
          } else if (type == TCA_CAKE_STATS_CAPACITY_ESTIMATE64 &&
                     mnl_attr_validate(cake_attr, MNL_TYPE_U64) >= 0) {
            capacity_estimate = mnl_attr_get_u64(cake_attr);
          } else if (type == TCA_CAKE_STATS_TIN_STATS) {
            tin_stats_attr = cake_attr;
          }
        }

        /* Submit global CAKE statistics as gauge values */
        char cake_inst[DATA_MAX_NAME_LEN];
        value_list_t vl = VALUE_LIST_INIT;
        value_t val;

        /* Submit memory-used */
        int status = ssnprintf(cake_inst, sizeof(cake_inst), "%s-memory-used", tc_inst);
        if (status >= sizeof(cake_inst)) {
          WARNING("netlink plugin: Instance name too long for CAKE memory-used metric, "
                  "truncated: %s-memory-used", tc_inst);
        }
        val.gauge = (gauge_t)memory_used;
        vl.values = &val;
        vl.values_len = 1;
        sstrncpy(vl.plugin, "netlink", sizeof(vl.plugin));
        sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
        sstrncpy(vl.type, "memory", sizeof(vl.type));
        sstrncpy(vl.type_instance, cake_inst, sizeof(vl.type_instance));
        plugin_dispatch_values(&vl);

        /* Submit memory-limit */
        status = ssnprintf(cake_inst, sizeof(cake_inst), "%s-memory-limit", tc_inst);
        if (status >= sizeof(cake_inst)) {
          WARNING("netlink plugin: Instance name too long for CAKE memory-limit metric, "
                  "truncated: %s-memory-limit", tc_inst);
        }
        val.gauge = (gauge_t)memory_limit;
        sstrncpy(vl.type_instance, cake_inst, sizeof(vl.type_instance));
        plugin_dispatch_values(&vl);

        /* Submit capacity-estimate */
        status = ssnprintf(cake_inst, sizeof(cake_inst), "%s-capacity", tc_inst);
        if (status >= sizeof(cake_inst)) {
          WARNING("netlink plugin: Instance name too long for CAKE capacity metric, "
                  "truncated: %s-capacity", tc_inst);
        }
        val.gauge = (gauge_t)capacity_estimate;
        sstrncpy(vl.type, "bitrate", sizeof(vl.type));
        sstrncpy(vl.type_instance, cake_inst, sizeof(vl.type_instance));
        plugin_dispatch_values(&vl);

        if (tin_stats_attr != NULL) {
          int tin_count = 0;
          struct nlattr *tin_attr;

          /* Iterate through tins - they are indexed starting from 1 */
          mnl_attr_for_each_nested(tin_attr, tin_stats_attr) {
            int tin_type = mnl_attr_get_type(tin_attr);

            /* tin_type is 1-based, convert to 0-based for naming */
            if (tin_type < 1 || tin_type > TC_CAKE_MAX_TINS)
              continue;

            int tin_idx = tin_type - 1;
            struct nlattr *stat_attr;

            /* Parse individual tin statistics */
            mnl_attr_for_each_nested(stat_attr, tin_attr) {
              int stat_type = mnl_attr_get_type(stat_attr);

              switch (stat_type) {
                case TCA_CAKE_TIN_STATS_SENT_BYTES64:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U64) >= 0) {
                    uint64_t bytes = mnl_attr_get_u64(stat_attr);
                    submit_cake_tin(dev, tc_inst, tin_idx, "ipt_bytes", NULL, (derive_t)bytes);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_SENT_PACKETS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t packets = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin(dev, tc_inst, tin_idx, "ipt_packets", NULL, (derive_t)packets);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_DROPPED_PACKETS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t dropped = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin(dev, tc_inst, tin_idx, "if_tx_dropped", NULL, (derive_t)dropped);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_ECN_MARKED_PACKETS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t ecn = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "gauge", "ecn-marked", (gauge_t)ecn);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_BACKLOG_BYTES:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t backlog_bytes = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "queue_length", "bytes", (gauge_t)backlog_bytes);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_BACKLOG_PACKETS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t backlog_packets = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "queue_length", "packets", (gauge_t)backlog_packets);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_SPARSE_FLOWS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t sparse = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "gauge", "sparse-flows", (gauge_t)sparse);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_BULK_FLOWS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t bulk = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "gauge", "bulk-flows", (gauge_t)bulk);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_UNRESPONSIVE_FLOWS:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t unresponsive = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "gauge", "unresponsive-flows", (gauge_t)unresponsive);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_PEAK_DELAY_US:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t peak_delay = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "delay", "peak", (gauge_t)peak_delay);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_AVG_DELAY_US:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t avg_delay = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "delay", "avg", (gauge_t)avg_delay);
                  }
                  break;

                case TCA_CAKE_TIN_STATS_BASE_DELAY_US:
                  if (mnl_attr_validate(stat_attr, MNL_TYPE_U32) >= 0) {
                    uint32_t base_delay = mnl_attr_get_u32(stat_attr);
                    submit_cake_tin_gauge(dev, tc_inst, tin_idx, "delay", "base", (gauge_t)base_delay);
                  }
                  break;
              }
            }

            tin_count++;
          }
        }
      }

      /* Process FQ extended stats from TCA_STATS_APP */
      if (q_stats.xstats != NULL && kind != NULL && strcmp(kind, "fq") == 0) {
        /* FQ xstats are a binary blob (struct tc_fq_qd_stats) directly in xstats payload */
        const void *xstats_data = mnl_attr_get_payload(q_stats.xstats);
        size_t xstats_len = mnl_attr_get_payload_len(q_stats.xstats);

        if (xstats_len >= sizeof(struct tc_fq_qd_stats)) {
          const struct tc_fq_qd_stats *fq_stats = (const struct tc_fq_qd_stats *)xstats_data;

          DEBUG("netlink plugin: FQ xstats for %s: flows=%u, throttled_flows=%u, throttled=%llu",
                dev, fq_stats->flows, fq_stats->throttled_flows,
                (unsigned long long)fq_stats->throttled);

          /* Submit FQ-specific stats as gauges and derives */
          char fq_inst[DATA_MAX_NAME_LEN];

          /* Gauges: Current state */
          int status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-flows", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-flows",
                    tc_inst);
          } else {
            submit_one_gauge(dev, "gauge", fq_inst, (gauge_t)fq_stats->flows);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-inactive-flows", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-inactive-flows",
                    tc_inst);
          } else {
            submit_one_gauge(dev, "gauge", fq_inst,
                           (gauge_t)fq_stats->inactive_flows);
          }

          status =
              ssnprintf(fq_inst, sizeof(fq_inst), "%s-throttled-flows", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-throttled-flows",
                    tc_inst);
          } else {
            submit_one_gauge(dev, "gauge", fq_inst,
                           (gauge_t)fq_stats->throttled_flows);
          }

          /* Derives: Cumulative counters */
          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-gc-flows", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-gc-flows",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst, (derive_t)fq_stats->gc_flows);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-throttled", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-throttled",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst, (derive_t)fq_stats->throttled);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-highprio", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-highprio",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst,
                       (derive_t)fq_stats->highprio_packets);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-tcp-retrans", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-tcp-retrans",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst, (derive_t)fq_stats->tcp_retrans);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-flows-plimit", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-flows-plimit",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst,
                       (derive_t)fq_stats->flows_plimit);
          }

          status =
              ssnprintf(fq_inst, sizeof(fq_inst), "%s-pkts-too-long", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-pkts-too-long",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst,
                       (derive_t)fq_stats->pkts_too_long);
          }

          status = ssnprintf(fq_inst, sizeof(fq_inst), "%s-ce-mark", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-ce-mark",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst, (derive_t)fq_stats->ce_mark);
          }

          status =
              ssnprintf(fq_inst, sizeof(fq_inst), "%s-horizon-drops", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-horizon-drops",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst,
                       (derive_t)fq_stats->horizon_drops);
          }

          status =
              ssnprintf(fq_inst, sizeof(fq_inst), "%s-horizon-caps", tc_inst);
          if (status < 0 || (size_t)status >= sizeof(fq_inst)) {
            WARNING("netlink plugin: Instance name too long for FQ metric, "
                    "truncated: %s-horizon-caps",
                    tc_inst);
          } else {
            submit_one(dev, "derive", fq_inst,
                       (derive_t)fq_stats->horizon_caps);
          }
        }
      }

      /* Process FQ_CODEL extended stats from TCA_STATS_APP */
      if (q_stats.xstats != NULL && kind != NULL &&
          strcmp(kind, "fq_codel") == 0) {
        /* FQ_CODEL xstats can be either qdisc stats or class stats (union) */
        const void *xstats_data = mnl_attr_get_payload(q_stats.xstats);
        size_t xstats_len = mnl_attr_get_payload_len(q_stats.xstats);

        if (xstats_len >= sizeof(struct tc_fq_codel_xstats)) {
          const struct tc_fq_codel_xstats *fqc_xstats =
              (const struct tc_fq_codel_xstats *)xstats_data;

          /* Check if it's qdisc stats (type == TCA_FQ_CODEL_XSTATS_QDISC) */
          if (fqc_xstats->type == TCA_FQ_CODEL_XSTATS_QDISC) {
            const struct tc_fq_codel_qd_stats *qd_stats =
                &fqc_xstats->qdisc_stats;

            DEBUG("netlink plugin: FQ_CODEL xstats for %s: new_flows=%u, "
                  "ecn_mark=%u",
                  dev, qd_stats->new_flow_count, qd_stats->ecn_mark);

            char fqc_inst[DATA_MAX_NAME_LEN];

            /* Gauges: Current state */
            int status = ssnprintf(fqc_inst, sizeof(fqc_inst),
                                   "%s-new-flows-len", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-new-flows-len",
                      tc_inst);
            } else {
              submit_one_gauge(dev, "gauge", fqc_inst,
                             (gauge_t)qd_stats->new_flows_len);
            }

            status = ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-old-flows-len",
                               tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-old-flows-len",
                      tc_inst);
            } else {
              submit_one_gauge(dev, "gauge", fqc_inst,
                             (gauge_t)qd_stats->old_flows_len);
            }

            status =
                ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-maxpacket", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-maxpacket",
                      tc_inst);
            } else {
              submit_one_gauge(dev, "gauge", fqc_inst,
                             (gauge_t)qd_stats->maxpacket);
            }

            status = ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-memory-usage",
                               tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-memory-usage",
                      tc_inst);
            } else {
              submit_one_gauge(dev, "memory", fqc_inst,
                             (gauge_t)qd_stats->memory_usage);
            }

            /* Derives: Cumulative counters */
            status = ssnprintf(fqc_inst, sizeof(fqc_inst),
                               "%s-new-flow-count", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-new-flow-count",
                      tc_inst);
            } else {
              submit_one(dev, "derive", fqc_inst,
                         (derive_t)qd_stats->new_flow_count);
            }

            status = ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-drop-overlimit",
                               tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-drop-overlimit",
                      tc_inst);
            } else {
              submit_one(dev, "derive", fqc_inst,
                         (derive_t)qd_stats->drop_overlimit);
            }

            status = ssnprintf(fqc_inst, sizeof(fqc_inst),
                               "%s-drop-overmemory", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-drop-overmemory",
                      tc_inst);
            } else {
              submit_one(dev, "derive", fqc_inst,
                         (derive_t)qd_stats->drop_overmemory);
            }

            status =
                ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-ecn-mark", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-ecn-mark",
                      tc_inst);
            } else {
              submit_one(dev, "derive", fqc_inst,
                         (derive_t)qd_stats->ecn_mark);
            }

            status = ssnprintf(fqc_inst, sizeof(fqc_inst), "%s-ce-mark", tc_inst);
            if (status < 0 || (size_t)status >= sizeof(fqc_inst)) {
              WARNING("netlink plugin: Instance name too long for FQ_CODEL "
                      "metric, truncated: %s-ce-mark",
                      tc_inst);
            } else {
              submit_one(dev, "derive", fqc_inst,
                         (derive_t)qd_stats->ce_mark);
            }
          }
        }
      }
    }

    break;
  }
#endif /* TCA_STATS2 */

#if HAVE_TCA_STATS
  mnl_attr_for_each(attr, nlh, sizeof(*tm)) {
    struct tc_stats *ts = NULL;

    if (mnl_attr_get_type(attr) != TCA_STATS)
      continue;

    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*ts)) < 0) {
      ERROR("netlink plugin: qos_filter_cb: TCA_STATS mnl_attr_validate2 "
            "failed: %s",
            STRERRNO);
      return MNL_CB_ERROR;
    }
    ts = mnl_attr_get_payload(attr);

    if (!stats_submitted && ts != NULL) {
      char type_instance[DATA_MAX_NAME_LEN];

      int r = ssnprintf(type_instance, sizeof(type_instance), "%s-%s", tc_type,
                        tc_inst);
      if ((size_t)r >= sizeof(type_instance)) {
        ERROR("netlink plugin: type_instance truncated to %zu bytes, need %d",
              sizeof(type_instance), r);
        return MNL_CB_ERROR;
      }

      submit_one(dev, "ipt_bytes", type_instance, ts->bytes);
      submit_one(dev, "ipt_packets", type_instance, ts->packets);
    }

    break;
  }

#endif /* TCA_STATS */

#if !(HAVE_TCA_STATS && HAVE_TCA_STATS2)
  DEBUG("netlink plugin: qos_filter_cb: Have neither TCA_STATS2 nor "
        "TCA_STATS.");
#endif

  return MNL_CB_OK;
} /* int qos_filter_cb */

/* Default buffer size for TC collection (256KB for systems with many qdiscs) */
#define NETLINK_TC_DEFAULT_BUF_SIZE (256 * 1024)

static size_t ir_get_buffer_size() {
  if (collect_vf_stats == false) {
    return NETLINK_TC_DEFAULT_BUF_SIZE;
  }

  glob_t g;
  unsigned int max_num = 0;
  if (glob("/sys/class/net/*/device/sriov_totalvfs", GLOB_NOSORT, NULL, &g)) {
    ERROR("netlink plugin: ir_get_buffer_size: glob failed");
    /* using default value */
    return NETLINK_VF_DEFAULT_BUF_SIZE_KB * 1024;
  }

  for (size_t i = 0; i < g.gl_pathc; i++) {
    char buf[16];
    ssize_t len;
    int num = 0;
    int fd = open(g.gl_pathv[i], O_RDONLY);
    if (fd < 0) {
      WARNING("netlink plugin: ir_get_buffer_size: failed to open `%s.`",
              g.gl_pathv[i]);
      continue;
    }

    if ((len = read(fd, buf, sizeof(buf) - 1)) <= 0) {
      WARNING("netlink plugin: ir_get_buffer_size: failed to read `%s.`",
              g.gl_pathv[i]);
      close(fd);
      continue;
    }
    buf[len] = '\0';

    if (sscanf(buf, "%d", &num) != 1) {
      WARNING("netlink plugin: ir_get_buffer_size: failed to read number from "
              "`%s.`",
              buf);
      close(fd);
      continue;
    }

    if (num > max_num)
      max_num = num;

    close(fd);
  }
  globfree(&g);
  DEBUG("netlink plugin: ir_get_buffer_size: max sriov_totalvfs = %u", max_num);

  unsigned int mp = NETLINK_VF_DEFAULT_BUF_SIZE_KB;
  /* allign to power of two, buffer size should be at least totalvfs/2 kb */
  while (mp < max_num / 2)
    mp *= 2;

  return mp * 1024;
}

static int ir_config(const char *key, const char *value) {
  char *new_val;
  char *fields[8];
  int fields_num;
  int status = 1;

  new_val = strdup(value);
  if (new_val == NULL)
    return -1;

  fields_num = strsplit(new_val, fields, STATIC_ARRAY_SIZE(fields));
  if ((fields_num < 1) || (fields_num > 8)) {
    sfree(new_val);
    return -1;
  }

  if ((strcasecmp(key, "Interface") == 0) ||
      (strcasecmp(key, "VerboseInterface") == 0)) {
    if (fields_num != 1) {
      ERROR("netlink plugin: Invalid number of fields for option "
            "`%s'. Got %i, expected 1.",
            key, fields_num);
      status = -1;
    } else {
      status = add_ignorelist(fields[0], "interface", NULL);
      if (strcasecmp(key, "VerboseInterface") == 0)
        status += add_ignorelist(fields[0], "if_detail", NULL);
    }
  } else if ((strcasecmp(key, "QDisc") == 0) ||
             (strcasecmp(key, "Class") == 0) ||
             (strcasecmp(key, "Filter") == 0)) {
    if (fields_num > 2) {
      ERROR("netlink plugin: Invalid number of fields for option "
            "`%s'. Got %i, expected 1 or 2.",
            key, fields_num);
      return -1;
    } else {
      status =
          add_ignorelist(fields[0], key, (fields_num == 2) ? fields[1] : NULL);
    }
  } else if (strcasecmp(key, "IgnoreSelected") == 0) {
    if (fields_num != 1) {
      ERROR("netlink plugin: Invalid number of fields for option "
            "`IgnoreSelected'. Got %i, expected 1.",
            fields_num);
      status = -1;
    } else {
      if (IS_TRUE(fields[0]))
        ir_ignorelist_invert = 0;
      else
        ir_ignorelist_invert = 1;
      status = 0;
    }
  } else if (strcasecmp(key, "CollectVFStats") == 0) {
    if (fields_num != 1) {
      ERROR("netlink plugin: Invalid number of fields for option "
            "`%s'. Got %i, expected 1.",
            key, fields_num);
      status = -1;
    } else {
#ifdef HAVE_IFLA_VF_STATS
      if (IS_TRUE(fields[0]))
        collect_vf_stats = true;
      else
        collect_vf_stats = false;
#else
      WARNING("netlink plugin: VF statistics not supported on this system.");
#endif
      status = 0;
    }
  }

  sfree(new_val);

  return status;
} /* int ir_config */

static int ir_init(void) {
  nl = mnl_socket_open(NETLINK_ROUTE);
  if (nl == NULL) {
    ERROR("netlink plugin: ir_init: mnl_socket_open failed.");
    return -1;
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    ERROR("netlink plugin: ir_init: mnl_socket_bind failed.");
    return -1;
  }

  nl_socket_buffer_size = ir_get_buffer_size();

  /* Set kernel socket receive buffer to handle large TC dumps */
  int rcvbuf = (int)nl_socket_buffer_size;
  int fd = mnl_socket_get_fd(nl);
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
    /* Try without FORCE if we're not root */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
      WARNING("netlink plugin: ir_init: setsockopt(SO_RCVBUF) failed: %s",
              strerror(errno));
    }
  }
  /* Verify actual buffer size */
  int actual_rcvbuf = 0;
  socklen_t optlen = sizeof(actual_rcvbuf);
  getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &optlen);
  INFO("netlink plugin: ir_init: socket rcvbuf = %d (requested %d)",
       actual_rcvbuf, rcvbuf);

  read_buffer = malloc(nl_socket_buffer_size);
  if (read_buffer == NULL) {
    ERROR("netlink plugin: ir_init: malloc failed for read buffer");
    mnl_socket_close(nl);
    nl = NULL;
    return -1;
  }

  INFO("netlink plugin: ir_init: buffer size = %zu", nl_socket_buffer_size);

  return 0;
} /* int ir_init */

static int ir_read(void) {
  char *buf = read_buffer;  /* Use pre-allocated buffer instead of VLA */
  struct nlmsghdr *nlh;
  struct rtgenmsg *rt;
  int ret;
  unsigned int seq, portid;

  static const int type_id[] = {RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER};
  static const char *type_name[] = {"qdisc", "class", "filter"};

  portid = mnl_socket_get_portid(nl);

  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = RTM_GETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nlh->nlmsg_seq = seq = time(NULL);
  rt = mnl_nlmsg_put_extra_header(nlh, sizeof(*rt));
  rt->rtgen_family = AF_PACKET;

#ifdef HAVE_IFLA_VF_STATS
  if (collect_vf_stats &&
      mnl_attr_put_u32_check(nlh, nl_socket_buffer_size, IFLA_EXT_MASK,
                             RTEXT_FILTER_VF) == 0) {
    ERROR("netlink plugin: FAILED to set RTEXT_FILTER_VF");
    return -1;
  }
#endif

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    ERROR("netlink plugin: ir_read: rtnl_wilddump_request failed.");
    return -1;
  }

  ret = mnl_socket_recvfrom(nl, buf, nl_socket_buffer_size);
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portid, link_filter_cb, NULL);
    if (ret <= MNL_CB_STOP)
      break;
    ret = mnl_socket_recvfrom(nl, buf, nl_socket_buffer_size);
  }
  if (ret < 0) {
    ERROR("netlink plugin: ir_read: mnl_socket_recvfrom failed: %s", STRERRNO);
    return (-1);
  }

  /* `link_filter_cb' will update `iflist' which is used here to iterate
   * over all interfaces. */
  for (size_t ifindex = 1; ifindex < iflist_len; ifindex++) {
    struct tcmsg *tm;

    if (iflist[ifindex] == NULL)
      continue;

    for (size_t type_index = 0; type_index < STATIC_ARRAY_SIZE(type_id);
         type_index++) {
      if (check_ignorelist(iflist[ifindex], type_name[type_index], NULL)) {
        DEBUG("netlink plugin: ir_read: check_ignorelist (%s, %s, (nil)) "
              "== TRUE",
              iflist[ifindex], type_name[type_index]);
        continue;
      }

      DEBUG("netlink plugin: ir_read: querying %s from %s (%" PRIsz ").",
            type_name[type_index], iflist[ifindex], ifindex);

      nlh = mnl_nlmsg_put_header(buf);
      nlh->nlmsg_type = type_id[type_index];
      nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
      nlh->nlmsg_seq = seq = time(NULL);
      tm = mnl_nlmsg_put_extra_header(nlh, sizeof(*tm));
      tm->tcm_family = AF_PACKET;
      tm->tcm_ifindex = ifindex;

      if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        ERROR("netlink plugin: ir_read: mnl_socket_sendto failed.");
        continue;
      }

      ret = mnl_socket_recvfrom(nl, buf, nl_socket_buffer_size);
      while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, qos_filter_cb, &ifindex);
        if (ret <= MNL_CB_STOP)
          break;
        ret = mnl_socket_recvfrom(nl, buf, nl_socket_buffer_size);
      }
      if (ret < 0) {
        ERROR("netlink plugin: ir_read: mnl_socket_recvfrom failed: %s",
              STRERRNO);
        continue;
      }
    } /* for (type_index) */
  }   /* for (if_index) */

  return 0;
} /* int ir_read */

static int ir_shutdown(void) {
  sfree(read_buffer);
  read_buffer = NULL;

  if (nl) {
    mnl_socket_close(nl);
    nl = NULL;
  }

  /* Free interface list */
  for (size_t i = 0; i < iflist_len; i++) {
    sfree(iflist[i]);
  }
  sfree(iflist);
  iflist = NULL;
  iflist_len = 0;

  ir_ignorelist_t *next = NULL;
  for (ir_ignorelist_t *i = ir_ignorelist_head; i != NULL; i = next) {
    next = i->next;
#if HAVE_REGEX_H
    if (i->rdevice != NULL) {
      regfree(i->rdevice);
      sfree(i->rdevice);
    }
#endif
    sfree(i->inst);
    sfree(i->type);
    sfree(i->device);
    sfree(i);
  }
  ir_ignorelist_head = NULL;

  return 0;
} /* int ir_shutdown */

void module_register(void) {
  plugin_register_config("netlink", ir_config, config_keys, config_keys_num);
  plugin_register_init("netlink", ir_init);
  plugin_register_read("netlink", ir_read);
  plugin_register_shutdown("netlink", ir_shutdown);
} /* void module_register */
