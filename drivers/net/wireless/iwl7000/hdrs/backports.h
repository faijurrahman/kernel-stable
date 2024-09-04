/*
 * ChromeOS backport definitions
 * Copyright (C) 2015-2017 Intel Deutschland GmbH
 * Copyright (C) 2018-2024 Intel Corporation
 */

/* backport wiphy_ext_feature_set/_isset
 *
 * To do so, define our own versions thereof that check for a negative
 * feature index and in that case ignore it entirely. That allows us to
 * define the ones that the cfg80211 version doesn't support to -1.
 */
static inline void iwl7000_wiphy_ext_feature_set(struct wiphy *wiphy, int ftidx)
{
	if (ftidx < 0)
		return;
	wiphy_ext_feature_set(wiphy, ftidx);
}

static inline bool iwl7000_wiphy_ext_feature_isset(struct wiphy *wiphy,
						   int ftidx)
{
	if (ftidx < 0)
		return false;
	return wiphy_ext_feature_isset(wiphy, ftidx);
}
#define wiphy_ext_feature_set iwl7000_wiphy_ext_feature_set
#define wiphy_ext_feature_isset iwl7000_wiphy_ext_feature_isset

#define NL80211_BAND_LC	5

#define skb_ext_reset LINUX_BACKPORT(skb_get_dsfield)
static inline int skb_get_dsfield(struct sk_buff *skb)
{
	switch (skb_protocol(skb, true)) {
	case cpu_to_be16(ETH_P_IP):
		if (!pskb_network_may_pull(skb, sizeof(struct iphdr)))
			break;
		return ipv4_get_dsfield(ip_hdr(skb));

	case cpu_to_be16(ETH_P_IPV6):
		if (!pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))
			break;
		return ipv6_get_dsfield(ipv6_hdr(skb));
	}

	return -1;
}

static inline void
cfg80211_assoc_comeback(struct net_device *netdev,
			struct cfg80211_bss *bss, u32 timeout)
{
}

#define rfkill_soft_blocked(__rfkill) rfkill_blocked(__rfkill)

static inline void __noreturn
kthread_complete_and_exit(struct completion *c, long ret)
{
	complete_and_exit(c, ret);
}

#define SKB_DROP_REASON_MAX	1

#define IEEE80211_CHAN_NO_HE 0
#define IEEE80211_CHAN_NO_EHT 0

#define NL80211_RRF_NO_HE 0

#define NL80211_CHAN_WIDTH_320 13

#define IEEE80211_EHT_PPE_THRES_MAX_LEN	32

struct ieee80211_eht_mcs_nss_supp {
	union {
		struct ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz;
		struct {
			struct ieee80211_eht_mcs_nss_supp_bw _80;
			struct ieee80211_eht_mcs_nss_supp_bw _160;
			struct ieee80211_eht_mcs_nss_supp_bw _320;
		} __packed bw;
	} __packed;
} __packed;

struct ieee80211_sta_eht_cap {
	bool has_eht;
	struct ieee80211_eht_cap_elem_fixed eht_cap_elem;
	struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp;
	u8 eht_ppe_thres[IEEE80211_EHT_PPE_THRES_MAX_LEN];
};

static inline const struct ieee80211_sta_eht_cap *
ieee80211_get_eht_iftype_cap(const struct ieee80211_supported_band *sband,
			     enum nl80211_iftype iftype)
{
	return NULL;
}

#define ieee80211_data_to_8023_exthdr iwl7000_ieee80211_data_to_8023_exthdr
int ieee80211_data_to_8023_exthdr(struct sk_buff *skb, struct ethhdr *ehdr,
				  const u8 *addr, enum nl80211_iftype iftype,
				  u8 data_offset, bool is_amsdu);

#define ieee80211_data_to_8023 iwl7000_ieee80211_data_to_8023
static inline int ieee80211_data_to_8023(struct sk_buff *skb, const u8 *addr,
					 enum nl80211_iftype iftype)
{
	return ieee80211_data_to_8023_exthdr(skb, NULL, addr, iftype, 0, false);
}

enum nl80211_eht_gi {
	NL80211_RATE_INFO_EHT_GI_0_8,
	NL80211_RATE_INFO_EHT_GI_1_6,
	NL80211_RATE_INFO_EHT_GI_3_2,
};

#define RATE_INFO_BW_320 (RATE_INFO_BW_HE_RU + 1)
#define NL80211_RRF_NO_320MHZ 0

/*
 * Same as SKB_DROP_REASON_NOT_SPECIFIED on some kernels,
 * but that's OK since we won't report these reasons to
 * the kernel anyway until 6.4, see kfree_skb_reason().
 */
#define SKB_NOT_DROPPED_YET	0

struct cfg80211_rx_info {
	int freq;
	int sig_dbm;
	bool have_link_id;
	u8 link_id;
	const u8 *buf;
	size_t len;
	u32 flags;
	u64 rx_tstamp;
	u64 ack_tstamp;
};

static inline bool cfg80211_rx_mgmt_ext(struct wireless_dev *wdev,
					struct cfg80211_rx_info *info)
{
	return cfg80211_rx_mgmt(wdev, KHZ_TO_MHZ(info->freq), info->sig_dbm,
				info->buf, info->len, info->flags);
}

/**
 * struct cfg80211_tx_status - TX status for management frame information
 *
 * @cookie: Cookie returned by cfg80211_ops::mgmt_tx()
 * @tx_tstamp: hardware TX timestamp in nanoseconds
 * @ack_tstamp: hardware ack RX timestamp in nanoseconds
 * @buf: Management frame (header + body)
 * @len: length of the frame data
 * @ack: Whether frame was acknowledged
 */
struct cfg80211_tx_status {
	u64 cookie;
	u64 tx_tstamp;
	u64 ack_tstamp;
	const u8 *buf;
	size_t len;
	bool ack;
};

static inline
void cfg80211_mgmt_tx_status_ext(struct wireless_dev *wdev,
				 struct cfg80211_tx_status *status, gfp_t gfp)
{
	cfg80211_mgmt_tx_status(wdev, status->cookie, status->buf, status->len,
				status->ack, gfp);
}

#ifdef CONFIG_THERMAL
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	return 0;
}
#endif /* CONFIG_THERMAL*/

static inline enum ieee80211_rate_flags
ieee80211_chanwidth_rate_flags(enum nl80211_chan_width width)
{
	switch (width) {
	case NL80211_CHAN_WIDTH_5:
		return IEEE80211_RATE_SUPPORTS_5MHZ;
	case NL80211_CHAN_WIDTH_10:
		return IEEE80211_RATE_SUPPORTS_10MHZ;
	default:
		break;
	}
	return 0;
}

#define WIPHY_FLAG_SUPPORTS_MLO 0

struct iwl7000_cfg80211_rx_assoc_resp {
	struct cfg80211_bss *bss;
	const u8 *buf;
	size_t len;
	const u8 *req_ies;
	size_t req_ies_len;
	int uapsd_queues;
	const u8 *ap_mld_addr;
	struct {
		u8 addr[ETH_ALEN];
		struct cfg80211_bss *bss;
		u16 status;
	} links[IEEE80211_MLD_MAX_NUM_LINKS];
};

static inline void
iwl7000_cfg80211_rx_assoc_resp(struct net_device *dev,
			       struct iwl7000_cfg80211_rx_assoc_resp *data)
{
	WARN_ON(data->ap_mld_addr);
	if (WARN_ON(!data->links[0].bss))
		return;

	cfg80211_rx_assoc_resp(dev, data->links[0].bss, data->buf, data->len,
			       data->uapsd_queues
#if LINUX_VERSION_IS_GEQ(5,1,0)
			       , data->req_ies, data->req_ies_len
#endif
			      );
}

#define cfg80211_rx_assoc_resp iwl7000_cfg80211_rx_assoc_resp

struct cfg80211_assoc_failure {
	const u8 *ap_mld_addr;
	struct cfg80211_bss *bss[IEEE80211_MLD_MAX_NUM_LINKS];
	bool timeout;
};

static inline void cfg80211_assoc_failure(struct net_device *dev,
					  struct cfg80211_assoc_failure *data)
{
	int i;

	WARN_ON(!data->bss[0]);
	WARN_ON(data->ap_mld_addr);

	for (i = 1; i < ARRAY_SIZE(data->bss); i++)
		WARN_ON(data->bss[i]);

	if (data->timeout)
		cfg80211_assoc_timeout(dev, data->bss[0]);
	else
		cfg80211_abandon_assoc(dev, data->bss[0]);
}

static inline const struct wiphy_iftype_ext_capab *
cfg80211_get_iftype_ext_capa(struct wiphy *wiphy, enum nl80211_iftype type)
{
	int i;

	for (i = 0; i < wiphy->num_iftype_ext_capab; i++) {
		if (wiphy->iftype_ext_capab[i].iftype == type)
			return &wiphy->iftype_ext_capab[i];
	}

	return NULL;
}

#define ASSOC_REQ_DISABLE_EHT BIT(5)
#define NL80211_EXT_FEATURE_POWERED_ADDR_CHANGE -1

static inline u16 get_random_u16(void)
{
	return get_random_int() & 0xffff;
}

static inline u32 get_random_u32_below(u32 ceil)
{
	return prandom_u32_max(ceil);
}

static inline u32 get_random_u32_inclusive(u32 floor, u32 ceil)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(floor) && __builtin_constant_p(ceil) &&
			 (floor > ceil || ceil - floor == U32_MAX),
			 "get_random_u32_inclusive() must take floor <= ceil");
	return floor + get_random_u32_below(ceil - floor + 1);
}

struct cfg80211_set_hw_timestamp {
	const u8 *macaddr;
	bool enable;
};

static inline void backport_netif_napi_add(struct net_device *dev,
					   struct napi_struct *napi,
					   int (*poll)(struct napi_struct *, int))
{
	netif_napi_add(dev, napi, poll, NAPI_POLL_WEIGHT);
}
#define netif_napi_add LINUX_BACKPORT(netif_napi_add)

bool cfg80211_valid_disable_subchannel_bitmap(u16 *bitmap,
					      struct cfg80211_chan_def *chandef);
#define ieee80211_amsdu_to_8023s(skb, list, addr, type, headroom, check_sa, check_da, mesh) \
	ieee80211_amsdu_to_8023s(skb, list, addr, type, headroom, check_sa, check_da)

#define SKB_CONSUMED (SKB_DROP_REASON_MAX + 1)
#define VISIBLE_IF_KUNIT static
#define EXPORT_SYMBOL_IF_KUNIT(...)

#define kvmemdup LINUX_BACKPORT(kvmemdup)
static inline void *kvmemdup(const void *src, size_t len, gfp_t gfp)
{
	void *p;

	p = kvmalloc(len, gfp);
	if (p)
		memcpy(p, src, len);
	return p;
}

#ifdef CONFIG_THERMAL
#include <linux/thermal.h>

#define thermal_zone_device_priv LINUX_BACKPORT(thermal_zone_device_priv)
static inline void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return tzd->devdata;
}
#endif

#define ieee80211_is_valid_amsdu LINUX_BACKPORT(ieee80211_is_valid_amsdu)
static inline bool ieee80211_is_valid_amsdu(struct sk_buff *skb, u8 mesh_hdr)
{
	return mesh_hdr == 0;
}

static inline void
LINUX_BACKPORT(kfree_skb_reason)(struct sk_buff *skb, u32 reason)
{
#if LINUX_VERSION_IS_LESS(5,17,0)
	dev_kfree_skb(skb);
#else
	kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
#endif
}
#define kfree_skb_reason LINUX_BACKPORT(kfree_skb_reason)

static inline bool
iwl7000_cfg80211_rx_control_port(struct net_device *dev, struct sk_buff *skb,
				 bool unencrypted, int link_id)
{
	return cfg80211_rx_control_port(dev, skb, unencrypted);
}
#define cfg80211_rx_control_port iwl7000_cfg80211_rx_control_port

enum skb_drop_reason_subsys {
	SKB_DROP_REASON_SUBSYS_CORE,
	SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE,
	SKB_DROP_REASON_SUBSYS_MAC80211_MONITOR,
	SKB_DROP_REASON_SUBSYS_NUM
};

struct drop_reason_list {
	const char * const *reasons;
	size_t n_reasons;
};

#define SKB_DROP_REASON_SUBSYS_SHIFT	16
#define SKB_DROP_REASON_SUBSYS_MASK	0xffff0000

static inline void
drop_reasons_register_subsys(enum skb_drop_reason_subsys subsys,
			     const struct drop_reason_list *list)
{}

static inline void
drop_reasons_unregister_subsys(enum skb_drop_reason_subsys subsys)
{}

#include <hdrs/linux/compiler_attributes.h>
#include <linux/leds.h>

#define NL80211_RRF_NO_EHT 0
static inline void
cfg80211_links_removed(struct net_device *dev, u16 removed_links)
{
}

static inline void backport_led_trigger_blink_oneshot(struct led_trigger *trigger,
						      unsigned long delay_on,
						      unsigned long delay_off,
						      int invert)
{
	led_trigger_blink_oneshot(trigger, &delay_on, &delay_off, invert);
}
#define led_trigger_blink_oneshot LINUX_BACKPORT(led_trigger_blink_oneshot)

static inline void backport_led_trigger_blink(struct led_trigger *trigger,
					      unsigned long delay_on,
					      unsigned long delay_off)
{
	led_trigger_blink(trigger, &delay_on, &delay_off);
}
#define led_trigger_blink LINUX_BACKPORT(led_trigger_blink)

#ifndef __cleanup
#define __cleanup(func) __attribute__((__cleanup__(func)))
#endif

void ieee80211_fragment_element(struct sk_buff *skb, u8 *len_pos, u8 frag_id);

static inline void
_ieee80211_set_sband_iftype_data(struct ieee80211_supported_band *sband,
				 const struct ieee80211_sband_iftype_data *iftd,
				 u16 n_iftd)
{
	sband->iftype_data = iftd;
	sband->n_iftype_data = n_iftd;
}

void wiphy_delayed_work_timer(struct timer_list *t);

#define wiphy_delayed_work_init LINUX_BACKPORT(wiphy_delayed_work_init)
static inline void wiphy_delayed_work_init(struct wiphy_delayed_work *dwork,
					   wiphy_work_func_t func)
{
	timer_setup(&dwork->timer, wiphy_delayed_work_timer, 0);
	wiphy_work_init(&dwork->work, func);
}

void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work);

void wiphy_delayed_work_queue(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork,
			      unsigned long delay);
void wiphy_delayed_work_cancel(struct wiphy *wiphy,
			       struct wiphy_delayed_work *dwork);

void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_delayed_work_flush(struct wiphy *wiphy,
			      struct wiphy_delayed_work *work);

#ifndef for_each_sband_iftype_data
#define for_each_sband_iftype_data(sband, i, iftd)	\
	for (i = 0, iftd = &(sband)->iftype_data[i];	\
	     i < (sband)->n_iftype_data;		\
	     i++, iftd = &(sband)->iftype_data[i])
#endif

/* older cfg80211 requires wdev to be locked */
#define WRAP_LOCKED(sym) wdev_locked_ ## sym

static inline void
WRAP_LOCKED(cfg80211_links_removed)(struct net_device *dev, u16 removed_links)
{
	mutex_lock(&dev->ieee80211_ptr->mtx);
	cfg80211_links_removed(dev, removed_links);
	mutex_unlock(&dev->ieee80211_ptr->mtx);
}
#define cfg80211_links_removed WRAP_LOCKED(cfg80211_links_removed)
static inline u32
iwl7000_ieee80211_mandatory_rates(struct ieee80211_supported_band *sband)
{
	return ieee80211_mandatory_rates(sband, NL80211_BSS_CHAN_WIDTH_20);
}
#define ieee80211_mandatory_rates iwl7000_ieee80211_mandatory_rates

static inline bool LINUX_BACKPORT(napi_schedule)(struct napi_struct *n)
{
	if (napi_schedule_prep(n)) {
		__napi_schedule(n);
		return true;
	}

	return false;
}
#define napi_schedule LINUX_BACKPORT(napi_schedule)

#ifdef CONFIG_CFG80211_DEBUGFS
static inline
ssize_t wiphy_locked_debugfs_read(struct wiphy *wiphy, struct file *file,
				  char *buf, size_t bufsize,
				  char __user *userbuf, size_t count,
				  loff_t *ppos,
				  ssize_t (*handler)(struct wiphy *wiphy,
						     struct file *file,
						     char *buf,
						     size_t bufsize,
						     void *data),
				  void *data)
{
	ssize_t ret = -EINVAL;

#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_lock(wiphy);
#else
	rtnl_lock();
#endif
	ret = handler(wiphy, file, buf, bufsize, data);
#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_unlock(wiphy);
#else
	rtnl_unlock();
#endif

	if (ret >= 0)
		ret = simple_read_from_buffer(userbuf, count, ppos, buf, ret);

	return ret;
}

static inline
ssize_t wiphy_locked_debugfs_write(struct wiphy *wiphy, struct file *file,
				   char *buf, size_t bufsize,
				   const char __user *userbuf, size_t count,
				   ssize_t (*handler)(struct wiphy *wiphy,
						      struct file *file,
						      char *buf,
						      size_t count,
						      void *data),
				   void *data)
{
	ssize_t ret;

	if (count >= sizeof(buf))
		return -E2BIG;

	if (copy_from_user(buf, userbuf, count))
		return -EFAULT;
	buf[count] = '\0';

#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_lock(wiphy);
#else
	rtnl_lock();
#endif
	ret = handler(wiphy, file, buf, bufsize, data);
#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_unlock(wiphy);
#else
	rtnl_unlock();
#endif

	return ret;
}
#endif
#define KUNIT_STATIC_STUB_REDIRECT(real_fn_name, args...) do {} while (0)

static inline void cfg80211_schedule_channels_check(struct wireless_dev *wdev)
{
}
#define NL80211_EXT_FEATURE_DFS_CONCURRENT -1
#define NL80211_RRF_DFS_CONCURRENT 0

struct cfg80211_ttlm_params {
	u16 dlink[8];
	u16 ulink[8];
};

bool
ieee80211_uhb_power_type_valid(struct ieee80211_mgmt *mgmt, size_t len,
			       struct ieee80211_channel *channel);

#define IEEE80211_CHAN_NO_6GHZ_VLP_CLIENT BIT(21)
#define IEEE80211_CHAN_NO_6GHZ_AFC_CLIENT BIT(22)

#define NL80211_RRF_NO_6GHZ_VLP_CLIENT BIT(22)
#define NL80211_RRF_NO_6GHZ_AFC_CLIENT BIT(23)

ssize_t cfg80211_defragment_element(const struct element *elem, const u8 *ies,
				    size_t ieslen, u8 *data, size_t data_len,
				    u8 frag_id);

enum cfg80211_rnr_iter_ret {
	RNR_ITER_CONTINUE,
	RNR_ITER_BREAK,
	RNR_ITER_ERROR,
};

bool cfg80211_iter_rnr(const u8 *elems, size_t elems_len,
		       enum cfg80211_rnr_iter_ret
		       (*iter)(void *data, u8 type,
			       const struct ieee80211_neighbor_ap_info *info,
			       const u8 *tbtt_info, u8 tbtt_info_len),
		       void *iter_data);

#if LINUX_VERSION_IS_LESS(6,0,0)
#define cfg80211_ch_switch_notify(dev, chandef, link_id) cfg80211_ch_switch_notify(dev, chandef)
#else
#define cfg80211_ch_switch_notify(dev, chandef, link_id) cfg80211_ch_switch_notify(dev, chandef, link_id, 0)
#endif

#define NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT -1
#define ASSOC_REQ_SPP_AMSDU BIT(7)
#define NL80211_STA_FLAG_SPP_AMSDU 8
bool ieee80211_operating_class_to_chandef(u8 operating_class,
					  struct ieee80211_channel *chan,
					  struct cfg80211_chan_def *chandef);

#define IEEE80211_CHAN_CAN_MONITOR 0

int nl80211_chan_width_to_mhz(enum nl80211_chan_width chan_width);
int cfg80211_chandef_primary(const struct cfg80211_chan_def *chandef,
			     enum nl80211_chan_width primary_width,
			     u16 *punctured);

#if LINUX_VERSION_IS_LESS(5,11,0)
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, count);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)

#elif LINUX_VERSION_IS_LESS(6,1,0)
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, count, quiet);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)
#else
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, link_id, count, quiet, 0);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)
#endif

#ifdef CONFIG_THERMAL
#define THERMAL_TRIP_FLAG_RW_TEMP       BIT(0)
static inline struct thermal_zone_device *
backport_thermal_zone_device_register_with_trips(const char *type,
						 struct thermal_trip *trips,
						 int num_trips, void *devdata,
						 struct thermal_zone_device_ops *ops,
						 struct thermal_zone_params *tzp,
						 int passive_delay,
						 int polling_delay)
{
#if LINUX_VERSION_IS_LESS(6,0,0)
	return thermal_zone_device_register(type, num_trips, 0, devdata, ops, tzp,
					    passive_delay, polling_delay);
#else
#undef thermal_trip
	return thermal_zone_device_register_with_trips(type,
						       (struct thermal_trip *)(void *) trips,
						       num_trips,
						       0, devdata,
						       ops, tzp, passive_delay,
						       polling_delay);
#define thermal_trip backport_thermal_trip
#endif /* < 6,6,0 */
#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
}

/* This function was added in 6,6,0 already, but struct thermal_trip isn't */
#if LINUX_VERSION_IS_GEQ(6,0,0)
#define for_each_thermal_trip LINUX_BACKPORT(for_each_thermal_trip)
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	struct thermal_trip *trip;
	struct thermal_trip *trips = (void *)tz->trips;
	int ret;

	for (trip = trips; trip - trips < tz->num_trips; trip++) {
		ret = cb(trip, data);
		if (ret)
			return ret;
	}

	return 0;
}
#endif /* >= 6,0,0 */
#endif /* CONFIG_THERMAL */

static inline struct net_device *alloc_netdev_dummy(int sizeof_priv)
{
	struct net_device *dev;
	dev = kzalloc(sizeof(*dev) +
		      ALIGN(sizeof(struct net_device), NETDEV_ALIGN) +
		      sizeof_priv,
		      GFP_KERNEL);
	if (!dev)
		return NULL;
	init_dummy_netdev(dev);
	return dev;
}

static inline void LINUX_BACKPORT(free_netdev)(struct net_device *dev)
{
	if (dev->reg_state == NETREG_DUMMY) {
		kfree(dev);
		return;
	}
	free_netdev(dev);
}
#define free_netdev LINUX_BACKPORT(free_netdev)


enum ieee80211_ap_reg_power {
	IEEE80211_REG_UNSET_AP,
	IEEE80211_REG_LPI_AP,
	IEEE80211_REG_SP_AP,
	IEEE80211_REG_VLP_AP,
};

/* upstream numbers */
#define NL80211_RRF_ALLOW_6GHZ_VLP_AP		BIT(24)
#define IEEE80211_CHAN_ALLOW_6GHZ_VLP_AP	BIT(25)

struct cfg80211_iface_usage {
	u32 types_mask;
};
