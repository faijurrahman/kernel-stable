/*
 * Copyright(c) 2015 - 2017 Intel Deutschland GmbH
 * Copyright (C) 2018, 2020, 2022-2024 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "mac80211-exp.h"

#include <linux/export.h>
#include <linux/if_vlan.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <asm/unaligned.h>
#include <linux/device.h>
#include <net/cfg80211.h>
#include "mac80211/ieee80211_i.h"
#include "mac80211/driver-ops.h"

static unsigned int __ieee80211_get_mesh_hdrlen(u8 flags)
{
	int ae = flags & MESH_FLAGS_AE;
	/* 802.11-2012, 8.2.4.7.3 */
	switch (ae) {
	default:
	case 0:
		return 6;
	case MESH_FLAGS_AE_A4:
		return 12;
	case MESH_FLAGS_AE_A5_A6:
		return 18;
	}
}

int ieee80211_data_to_8023_exthdr(struct sk_buff *skb, struct ethhdr *ehdr,
				  const u8 *addr, enum nl80211_iftype iftype,
				  u8 data_offset, bool is_amsdu)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct {
		u8 hdr[ETH_ALEN] __aligned(2);
		__be16 proto;
	} payload;
	struct ethhdr tmp;
	u16 hdrlen;
	u8 mesh_flags = 0;

	if (unlikely(!ieee80211_is_data_present(hdr->frame_control)))
		return -1;

	hdrlen = ieee80211_hdrlen(hdr->frame_control) + data_offset;
	if (skb->len < hdrlen + 8)
		return -1;

	/* convert IEEE 802.11 header + possible LLC headers into Ethernet
	 * header
	 * IEEE 802.11 address fields:
	 * ToDS FromDS Addr1 Addr2 Addr3 Addr4
	 *   0     0   DA    SA    BSSID n/a
	 *   0     1   DA    BSSID SA    n/a
	 *   1     0   BSSID SA    DA    n/a
	 *   1     1   RA    TA    DA    SA
	 */
	memcpy(tmp.h_dest, ieee80211_get_DA(hdr), ETH_ALEN);
	memcpy(tmp.h_source, ieee80211_get_SA(hdr), ETH_ALEN);

	if (iftype == NL80211_IFTYPE_MESH_POINT)
		skb_copy_bits(skb, hdrlen, &mesh_flags, 1);

	mesh_flags &= MESH_FLAGS_AE;

	switch (hdr->frame_control &
		cpu_to_le16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
	case cpu_to_le16(IEEE80211_FCTL_TODS):
		if (unlikely(iftype != NL80211_IFTYPE_AP &&
			     iftype != NL80211_IFTYPE_AP_VLAN &&
			     iftype != NL80211_IFTYPE_P2P_GO))
			return -1;
		break;
	case cpu_to_le16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS):
		if (unlikely(iftype != NL80211_IFTYPE_MESH_POINT &&
			     iftype != NL80211_IFTYPE_AP_VLAN &&
			     iftype != NL80211_IFTYPE_STATION))
			return -1;
		if (iftype == NL80211_IFTYPE_MESH_POINT) {
			if (mesh_flags == MESH_FLAGS_AE_A4)
				return -1;
			if (mesh_flags == MESH_FLAGS_AE_A5_A6) {
				skb_copy_bits(skb, hdrlen +
					offsetof(struct ieee80211s_hdr, eaddr1),
					tmp.h_dest, 2 * ETH_ALEN);
			}
			hdrlen += __ieee80211_get_mesh_hdrlen(mesh_flags);
		}
		break;
	case cpu_to_le16(IEEE80211_FCTL_FROMDS):
		if ((iftype != NL80211_IFTYPE_STATION &&
		     iftype != NL80211_IFTYPE_P2P_CLIENT &&
		     iftype != NL80211_IFTYPE_MESH_POINT) ||
		    (is_multicast_ether_addr(tmp.h_dest) &&
		     ether_addr_equal(tmp.h_source, addr)))
			return -1;
		if (iftype == NL80211_IFTYPE_MESH_POINT) {
			if (mesh_flags == MESH_FLAGS_AE_A5_A6)
				return -1;
			if (mesh_flags == MESH_FLAGS_AE_A4)
				skb_copy_bits(skb, hdrlen +
					offsetof(struct ieee80211s_hdr, eaddr1),
					tmp.h_source, ETH_ALEN);
			hdrlen += __ieee80211_get_mesh_hdrlen(mesh_flags);
		}
		break;
	case cpu_to_le16(0):
		if (iftype != NL80211_IFTYPE_ADHOC &&
		    iftype != NL80211_IFTYPE_STATION &&
		    iftype != NL80211_IFTYPE_OCB)
			return -1;
		break;
	}

	skb_copy_bits(skb, hdrlen, &payload, sizeof(payload));
	tmp.h_proto = payload.proto;

	if (likely((!is_amsdu && ether_addr_equal(payload.hdr, rfc1042_header) &&
		    tmp.h_proto != htons(ETH_P_AARP) &&
		    tmp.h_proto != htons(ETH_P_IPX)) ||
		   ether_addr_equal(payload.hdr, bridge_tunnel_header))) {
		/* remove RFC1042 or Bridge-Tunnel encapsulation and
		 * replace EtherType */
		hdrlen += ETH_ALEN + 2;
		skb_postpull_rcsum(skb, &payload, ETH_ALEN + 2);
	} else {
		tmp.h_proto = htons(skb->len - hdrlen);
	}

	pskb_pull(skb, hdrlen);

	if (!ehdr)
		ehdr = skb_push(skb, sizeof(struct ethhdr));
	memcpy(ehdr, &tmp, sizeof(tmp));

	return 0;
}
EXPORT_SYMBOL(/* don't auto-generate a rename */
	ieee80211_data_to_8023_exthdr);

struct ieee80211_per_bw_puncturing_values {
	u8 len;
	const u16 *valid_values;
};

static const u16 puncturing_values_80mhz[] = {
	0x8, 0x4, 0x2, 0x1
};

static const u16 puncturing_values_160mhz[] = {
	 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1, 0xc0, 0x30, 0xc, 0x3
};

static const u16 puncturing_values_320mhz[] = {
	0xc000, 0x3000, 0xc00, 0x300, 0xc0, 0x30, 0xc, 0x3, 0xf000, 0xf00,
	0xf0, 0xf, 0xfc00, 0xf300, 0xf0c0, 0xf030, 0xf00c, 0xf003, 0xc00f,
	0x300f, 0xc0f, 0x30f, 0xcf, 0x3f
};

#define IEEE80211_PER_BW_VALID_PUNCTURING_VALUES(_bw) \
	{ \
		.len = ARRAY_SIZE(puncturing_values_ ## _bw ## mhz), \
		.valid_values = puncturing_values_ ## _bw ## mhz \
	}

static const struct ieee80211_per_bw_puncturing_values per_bw_puncturing[] = {
	IEEE80211_PER_BW_VALID_PUNCTURING_VALUES(80),
	IEEE80211_PER_BW_VALID_PUNCTURING_VALUES(160),
	IEEE80211_PER_BW_VALID_PUNCTURING_VALUES(320)
};

static bool
ieee80211_valid_disable_subchannel_bitmap(u16 *bitmap, enum nl80211_chan_width bw)
{
	u32 idx, i;

	switch((int)bw) {
	case NL80211_CHAN_WIDTH_80:
		idx = 0;
		break;
	case NL80211_CHAN_WIDTH_160:
		idx = 1;
		break;
	case NL80211_CHAN_WIDTH_320:
		idx = 2;
		break;
	default:
		*bitmap = 0;
		break;
	}

	if (!*bitmap)
		return true;

	for (i = 0; i < per_bw_puncturing[idx].len; i++)
		if (per_bw_puncturing[idx].valid_values[i] == *bitmap)
			return true;

	return false;
}

bool cfg80211_valid_disable_subchannel_bitmap(u16 *bitmap,
					      struct cfg80211_chan_def *chandef)
{
	return ieee80211_valid_disable_subchannel_bitmap(bitmap, chandef->width);
}

static void cfg80211_wiphy_work(struct work_struct *work)
{
	struct ieee80211_local *local;
	struct wiphy_work *wk;

	local = container_of(work, struct ieee80211_local, wiphy_work);

#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_lock();
#else
	wiphy_lock(local->hw.wiphy);
#endif
	if (local->suspended)
		goto out;

	spin_lock_irq(&local->wiphy_work_lock);
	wk = list_first_entry_or_null(&local->wiphy_work_list,
				      struct wiphy_work, entry);
	if (wk) {
		list_del_init(&wk->entry);
		if (!list_empty(&local->wiphy_work_list))
			schedule_work(work);
		spin_unlock_irq(&local->wiphy_work_lock);

		wk->func(local->hw.wiphy, wk);
	} else {
		spin_unlock_irq(&local->wiphy_work_lock);
	}
out:
#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_unlock();
#else
	wiphy_unlock(local->hw.wiphy);
#endif
}

void wiphy_work_setup(struct ieee80211_local *local)
{
	INIT_WORK(&local->wiphy_work, cfg80211_wiphy_work);
	INIT_LIST_HEAD(&local->wiphy_work_list);
	spin_lock_init(&local->wiphy_work_lock);
}

void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *end)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	struct wiphy_work *wk;
	unsigned long flags;
	int runaway_limit = 100;

	lockdep_assert_wiphy(wiphy);

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	while (!list_empty(&local->wiphy_work_list)) {
		struct wiphy_work *wk;

		wk = list_first_entry(&local->wiphy_work_list,
				      struct wiphy_work, entry);
		list_del_init(&wk->entry);
		spin_unlock_irqrestore(&local->wiphy_work_lock, flags);

		wk->func(local->hw.wiphy, wk);

		spin_lock_irqsave(&local->wiphy_work_lock, flags);

		if (wk == end)
			break;

		if (WARN_ON(--runaway_limit == 0))
			INIT_LIST_HEAD(&local->wiphy_work_list);
	}
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);
}
EXPORT_SYMBOL(wiphy_work_flush);

void wiphy_delayed_work_flush(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork)
{
	del_timer_sync(&dwork->timer);
	wiphy_work_flush(wiphy, &dwork->work);
}
EXPORT_SYMBOL(wiphy_delayed_work_flush);

void wiphy_work_teardown(struct ieee80211_local *local)
{
#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_lock();
#else
	wiphy_lock(local->hw.wiphy);
#endif

	wiphy_work_flush(local->hw.wiphy, NULL);

#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_unlock();
#else
	wiphy_unlock(local->hw.wiphy);
#endif

	cancel_work_sync(&local->wiphy_work);
}

void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	unsigned long flags;

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	if (list_empty(&work->entry))
		list_add_tail(&work->entry, &local->wiphy_work_list);
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);

	schedule_work(&local->wiphy_work);
}
EXPORT_SYMBOL_GPL(wiphy_work_queue);

void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	unsigned long flags;

#if LINUX_VERSION_IS_LESS(5,12,0)
	ASSERT_RTNL();
#else
	lockdep_assert_held(&wiphy->mtx);
#endif

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	if (!list_empty(&work->entry))
		list_del_init(&work->entry);
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);
}
EXPORT_SYMBOL_GPL(wiphy_work_cancel);

void wiphy_delayed_work_timer(struct timer_list *t)
{
	struct wiphy_delayed_work *dwork = from_timer(dwork, t, timer);

	wiphy_work_queue(dwork->wiphy, &dwork->work);
}
EXPORT_SYMBOL(wiphy_delayed_work_timer);

void wiphy_delayed_work_queue(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork,
			      unsigned long delay)
{
	if (!delay) {
		del_timer(&dwork->timer);
		wiphy_work_queue(wiphy, &dwork->work);
		return;
	}

	dwork->wiphy = wiphy;
	mod_timer(&dwork->timer, jiffies + delay);
}
EXPORT_SYMBOL_GPL(wiphy_delayed_work_queue);

void wiphy_delayed_work_cancel(struct wiphy *wiphy,
			       struct wiphy_delayed_work *dwork)
{
#if LINUX_VERSION_IS_LESS(5,12,0)
	ASSERT_RTNL();
#else
	lockdep_assert_held(&wiphy->mtx);
#endif

	del_timer_sync(&dwork->timer);
	wiphy_work_cancel(wiphy, &dwork->work);
}
EXPORT_SYMBOL_GPL(wiphy_delayed_work_cancel);

void ieee80211_fragment_element(struct sk_buff *skb, u8 *len_pos, u8 frag_id)
{
	unsigned int elem_len;

	if (!len_pos)
		return;

	elem_len = skb->data + skb->len - len_pos - 1;

	while (elem_len > 255) {
		/* this one is 255 */
		*len_pos = 255;
		/* remaining data gets smaller */
		elem_len -= 255;
		/* make space for the fragment ID/len in SKB */
		skb_put(skb, 2);
		/* shift back the remaining data to place fragment ID/len */
		memmove(len_pos + 255 + 3, len_pos + 255 + 1, elem_len);
		/* place the fragment ID */
		len_pos += 255 + 1;
		*len_pos = frag_id;
		/* and point to fragment length to update later */
		len_pos++;
	}

	*len_pos = elem_len;
}
EXPORT_SYMBOL(ieee80211_fragment_element);

int nl80211_chan_width_to_mhz(enum nl80211_chan_width chan_width)
{
	int mhz;

	switch((int)chan_width) {
	case NL80211_CHAN_WIDTH_1:
		mhz = 1;
		break;
	case NL80211_CHAN_WIDTH_2:
		mhz = 2;
		break;
	case NL80211_CHAN_WIDTH_4:
		mhz = 4;
		break;
	case NL80211_CHAN_WIDTH_8:
		mhz = 8;
		break;
	case NL80211_CHAN_WIDTH_16:
		mhz = 16;
		break;
	case NL80211_CHAN_WIDTH_5:
		mhz = 5;
		break;
	case NL80211_CHAN_WIDTH_10:
		mhz = 10;
		break;
	case NL80211_CHAN_WIDTH_20:
	case NL80211_CHAN_WIDTH_20_NOHT:
		mhz = 20;
		break;
	case NL80211_CHAN_WIDTH_40:
		mhz = 40;
		break;
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_80:
		mhz = 80;
		break;
	case NL80211_CHAN_WIDTH_160:
		mhz = 160;
		break;
	case NL80211_CHAN_WIDTH_320:
		mhz = 320;
		break;
	default:
		WARN_ON_ONCE(1);
		return -1;
	}
	return mhz;
}
EXPORT_SYMBOL_GPL(nl80211_chan_width_to_mhz);

static int cfg80211_chandef_get_width(const struct cfg80211_chan_def *c)
{
	return nl80211_chan_width_to_mhz(c->width);
}

int cfg80211_chandef_primary(const struct cfg80211_chan_def *c,
			     enum nl80211_chan_width primary_chan_width,
			     u16 *punctured)
{
	int pri_width = nl80211_chan_width_to_mhz(primary_chan_width);
	int width = cfg80211_chandef_get_width(c);
	u32 control = c->chan->center_freq;
	u32 center = c->center_freq1;
	u16 _punct = 0;

	if (WARN_ON_ONCE(pri_width < 0 || width < 0))
		return -1;

	/* not intended to be called this way, can't determine */
	if (WARN_ON_ONCE(pri_width > width))
		return -1;

	if (!punctured)
		punctured = &_punct;

#if LINUX_VERSION_IS_GEQ(6,9,0)
	*punctured = 0;
#endif

	while (width > pri_width) {
		unsigned int bits_to_drop = width / 20 / 2;

		if (control > center) {
			center += width / 4;
			*punctured >>= bits_to_drop;
		} else {
			center -= width / 4;
			*punctured &= (1 << bits_to_drop) - 1;
		}
		width /= 2;
	}

	return center;
}

bool
ieee80211_uhb_power_type_valid(struct ieee80211_mgmt *mgmt, size_t len,
			       struct ieee80211_channel *channel)
{
	const struct element *tmp;
	struct ieee80211_he_operation *he_oper;
	bool ret = false;
	size_t ielen, min_hdr_len;
	u8 *variable = mgmt->u.probe_resp.variable;

	min_hdr_len = offsetof(struct ieee80211_mgmt,
			       u.probe_resp.variable);
	ielen = len - min_hdr_len;

	if (channel->band != NL80211_BAND_6GHZ)
		return true;

	tmp = cfg80211_find_ext_elem(WLAN_EID_EXT_HE_OPERATION,
				     variable, ielen);
	if (tmp && tmp->datalen >= sizeof(*he_oper) + 1) {
		const struct ieee80211_he_6ghz_oper *he_6ghz_oper;

		he_oper = (void *)&tmp->data[1];
		he_6ghz_oper = ieee80211_he_6ghz_oper(he_oper);
		if (!he_6ghz_oper)
			return false;

		switch (u8_get_bits(he_6ghz_oper->control,
				    IEEE80211_HE_6GHZ_OPER_CTRL_REG_INFO)) {
		case IEEE80211_6GHZ_CTRL_REG_LPI_AP:
		case IEEE80211_6GHZ_CTRL_REG_INDOOR_LPI_AP:
			return true;
		case IEEE80211_6GHZ_CTRL_REG_SP_AP:
		case IEEE80211_6GHZ_CTRL_REG_INDOOR_SP_AP:
			return !(channel->flags &
				 IEEE80211_CHAN_NO_6GHZ_AFC_CLIENT);
		case IEEE80211_6GHZ_CTRL_REG_VLP_AP:
			return !(channel->flags &
				 IEEE80211_CHAN_NO_6GHZ_VLP_CLIENT);
		default:
			return false;
		}
	}
	return false;
}

bool cfg80211_iter_rnr(const u8 *elems, size_t elems_len,
		       enum cfg80211_rnr_iter_ret
		       (*iter)(void *data, u8 type,
			       const struct ieee80211_neighbor_ap_info *info,
			       const u8 *tbtt_info, u8 tbtt_info_len),
		       void *iter_data)
{
	const struct element *rnr;
	const u8 *pos, *end;

	for_each_element_id(rnr, WLAN_EID_REDUCED_NEIGHBOR_REPORT,
			    elems, elems_len) {
		const struct ieee80211_neighbor_ap_info *info;

		pos = rnr->data;
		end = rnr->data + rnr->datalen;

		/* RNR IE may contain more than one NEIGHBOR_AP_INFO */
		while (sizeof(*info) <= end - pos) {
			u8 length, i, count;
			u8 type;

			info = (void *)pos;
			count = u8_get_bits(info->tbtt_info_hdr,
					    IEEE80211_AP_INFO_TBTT_HDR_COUNT) +
				1;
			length = info->tbtt_info_len;

			pos += sizeof(*info);

			if (count * length > end - pos)
				return false;

			type = u8_get_bits(info->tbtt_info_hdr,
					   IEEE80211_AP_INFO_TBTT_HDR_TYPE);

			for (i = 0; i < count; i++) {
				switch (iter(iter_data, type, info,
					     pos, length)) {
				case RNR_ITER_CONTINUE:
					break;
				case RNR_ITER_BREAK:
					return true;
				case RNR_ITER_ERROR:
					return false;
				}

				pos += length;
			}
		}

		if (pos != end)
			return false;
	}

	return true;
}

ssize_t cfg80211_defragment_element(const struct element *elem, const u8 *ies,
				    size_t ieslen, u8 *data, size_t data_len,
				    u8 frag_id)
{
	const struct element *next;
	ssize_t copied;
	u8 elem_datalen;

	if (!elem)
		return -EINVAL;

	/* elem might be invalid after the memmove */
	next = (void *)(elem->data + elem->datalen);
	elem_datalen = elem->datalen;

	if (elem->id == WLAN_EID_EXTENSION) {
		copied = elem->datalen - 1;

		if (data) {
			if (copied > data_len)
				return -ENOSPC;

			memmove(data, elem->data + 1, copied);
		}
	} else {
		copied = elem->datalen;

		if (data) {
			if (copied > data_len)
				return -ENOSPC;

			memmove(data, elem->data, copied);
		}
	}

	/* Fragmented elements must have 255 bytes */
	if (elem_datalen < 255)
		return copied;

	for (elem = next;
	     elem->data < ies + ieslen &&
		elem->data + elem->datalen <= ies + ieslen;
	     elem = next) {
		/* elem might be invalid after the memmove */
		next = (void *)(elem->data + elem->datalen);

		if (elem->id != frag_id)
			break;

		elem_datalen = elem->datalen;

		if (data) {
			if (copied + elem_datalen > data_len)
				return -ENOSPC;

			memmove(data + copied, elem->data, elem_datalen);
		}

		copied += elem_datalen;

		/* Only the last fragment may be short */
		if (elem_datalen != 255)
			break;
	}

	return copied;
}
EXPORT_SYMBOL(cfg80211_defragment_element);

bool ieee80211_operating_class_to_chandef(u8 operating_class,
					  struct ieee80211_channel *chan,
					  struct cfg80211_chan_def *chandef)
{
	u32 control_freq, offset = 0;
	enum nl80211_band band;

	if (!ieee80211_operating_class_to_band(operating_class, &band) ||
	    !chan || band != chan->band)
		return false;

	control_freq = chan->center_freq;
	chandef->chan = chan;

	if (control_freq >= 5955)
		offset = control_freq - 5955;
	else if (control_freq >= 5745)
		offset = control_freq - 5745;
	else if (control_freq >= 5180)
		offset = control_freq - 5180;
	offset /= 20;

	switch (operating_class) {
	case 81:  /* 2 GHz band; 20 MHz; channels 1..13 */
	case 82:  /* 2 GHz band; 20 MHz; channel 14 */
	case 115: /* 5 GHz band; 20 MHz; channels 36,40,44,48 */
	case 118: /* 5 GHz band; 20 MHz; channels 52,56,60,64 */
	case 121: /* 5 GHz band; 20 MHz; channels 100..144 */
	case 124: /* 5 GHz band; 20 MHz; channels 149,153,157,161 */
	case 125: /* 5 GHz band; 20 MHz; channels 149..177 */
	case 131: /* 6 GHz band; 20 MHz; channels 1..233*/
	case 136: /* 6 GHz band; 20 MHz; channel 2 */
		chandef->center_freq1 = control_freq;
		chandef->width = NL80211_CHAN_WIDTH_20;
		return true;
	case 83:  /* 2 GHz band; 40 MHz; channels 1..9 */
	case 116: /* 5 GHz band; 40 MHz; channels 36,44 */
	case 119: /* 5 GHz band; 40 MHz; channels 52,60 */
	case 122: /* 5 GHz band; 40 MHz; channels 100,108,116,124,132,140 */
	case 126: /* 5 GHz band; 40 MHz; channels 149,157,165,173 */
		chandef->center_freq1 = control_freq + 10;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 84:  /* 2 GHz band; 40 MHz; channels 5..13 */
	case 117: /* 5 GHz band; 40 MHz; channels 40,48 */
	case 120: /* 5 GHz band; 40 MHz; channels 56,64 */
	case 123: /* 5 GHz band; 40 MHz; channels 104,112,120,128,136,144 */
	case 127: /* 5 GHz band; 40 MHz; channels 153,161,169,177 */
		chandef->center_freq1 = control_freq - 10;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 132: /* 6 GHz band; 40 MHz; channels 1,5,..,229*/
		chandef->center_freq1 = control_freq + 10 - (offset & 1) * 20;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 128: /* 5 GHz band; 80 MHz; channels 36..64,100..144,149..177 */
	case 133: /* 6 GHz band; 80 MHz; channels 1,5,..,229 */
		chandef->center_freq1 = control_freq + 30 - (offset & 3) * 20;
		chandef->width = NL80211_CHAN_WIDTH_80;
		return true;
	case 129: /* 5 GHz band; 160 MHz; channels 36..64,100..144,149..177 */
	case 134: /* 6 GHz band; 160 MHz; channels 1,5,..,229 */
		chandef->center_freq1 = control_freq + 70 - (offset & 7) * 20;
		chandef->width = NL80211_CHAN_WIDTH_160;
		return true;
	case 130: /* 5 GHz band; 80+80 MHz; channels 36..64,100..144,149..177 */
	case 135: /* 6 GHz band; 80+80 MHz; channels 1,5,..,229 */
		  /* The center_freq2 of 80+80 MHz is unknown */
	case 137: /* 6 GHz band; 320 MHz; channels 1,5,..,229 */
		  /* 320-1 or 320-2 channelization is unknown */
	default:
		return false;
	}
}
