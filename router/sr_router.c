/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO - Done: Add constant definitions here... */

/* TODO - Done: Add helper functions here... */

struct sr_rt* longestPrefixLookup(struct sr_instance* sr, uint32_t ip) {
  struct sr_rt* rte = sr->routing_table;
  struct sr_rt* so_far = NULL;
  uint32_t last_mask = 0;
  while (rte) {
    if (rte->mask.s_addr > last_mask && 
        (ntohl(rte->mask.s_addr) ^ (ip)) == 
        (ntohl(rte->mask.s_addr) ^ ntohl(rte->dest.s_addr))) {
      last_mask = rte->mask.s_addr;
      so_far = rte;
    }
    rte = rte->next;
  }
  return so_far;
}

struct sr_if* find_interface_by_ip(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* iface = sr->if_list;
  if (ip == 0) {
    return NULL;
  }
  while (iface) {
    if (ntohl(iface->ip) == ntohl(ip)) {
      return iface;
    }
    iface = iface->next;
  }
  return NULL;

}

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    sr_ethernet_hdr_t *e_hdr;
    sr_ip_hdr_t* ip_hdr;
    uint8_t* to_send;
    sr_arp_hdr_t *arp_reply;
    struct sr_if* iface;
    struct sr_rt* rt;
    struct sr_packet *packet;
    uint32_t temp_ip;
    sr_icmp_t3_hdr_t *icmp3_hdr;
    size_t size;


    if (difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
          /* TODO - Done need to test
          send icmp host unreachable */
          packet = req->packets;
          while (packet) {

            /* special handling because the packet may be shorter than an ICMP */
            size = packet->len;
            if (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) < size) {
              size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            }
            to_send = (uint8_t*)calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            memcpy(to_send, packet->buf, size);

            /* ethernet part */
            e_hdr = (sr_ethernet_hdr_t*)to_send;
            memcpy(e_hdr->ether_shost, sr_get_interface(sr, packet->iface)->addr, ETHER_ADDR_LEN);

            /* ip part */
            ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
            temp_ip = ip_hdr->ip_dst;
            ip_hdr->ip_dst = ip_hdr->ip_src;
            ip_hdr->ip_src = temp_ip;
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_p = ip_protocol_icmp;
            ip_hdr->ip_len = ntohs(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            /* icmp part */
            icmp3_hdr = (sr_icmp_t3_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp3_hdr->icmp_type = 3;
            icmp3_hdr->icmp_code = 1;
            icmp3_hdr->icmp_sum = 0;
            memcpy(icmp3_hdr->data, (uint8_t*)(packet->buf + sizeof(sr_ethernet_hdr_t)), ICMP_DATA_SIZE);
            icmp3_hdr->icmp_sum = cksum(icmp3_hdr, sizeof(sr_icmp_t3_hdr_t));
            
            /* send and cleanup */
            sr_send_packet(sr, to_send, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), packet->iface);
            free(to_send);
            packet = packet->next;
          }

          sr_arpreq_destroy(&sr->cache, req);
          return;
        }
        else {
          /* TODO - Done
          send arp request 
          */

          rt = longestPrefixLookup(sr, ntohl(req->ip));
          if (rt == NULL) {
            /* TODO something probably went wrong if we're here in this case */
            return;
          }
          iface = sr_get_interface(sr, rt->interface);
          if (iface == NULL) {
            /* TODO something probably went wrong if we're here in this case */
            return;
          }

          /* ethernet part */
          to_send = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
          e_hdr = (sr_ethernet_hdr_t*)to_send;
          memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          e_hdr->ether_type = ntohs(ethertype_arp);

          /* arp part */
          arp_reply = (sr_arp_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
          arp_reply->ar_hrd = ntohs(arp_hrd_ethernet);
          arp_reply->ar_pro = ntohs(2048);
          arp_reply->ar_hln = ETHER_ADDR_LEN;
          arp_reply->ar_pln = 4;
          arp_reply->ar_op = ntohs(arp_op_request);
          memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
          arp_reply->ar_sip = iface->ip;
          memset(arp_reply->ar_tha, 0x00, ETHER_ADDR_LEN);
          arp_reply->ar_tip = req->ip; 

          /* send and cleanup */
          sr_send_packet(sr, to_send, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
          free(to_send);

          req->sent = now;
          req->times_sent++;
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  struct sr_packet* e_packet;
  sr_ethernet_hdr_t* e_hdr, e_reply;
  uint16_t ether_type;
  sr_arp_hdr_t* arp_hdr, arp_reply;
  sr_ip_hdr_t* ip_hdr, ip_reply;
  sr_icmp_hdr_t* icmp_hdr, icmp_reply, *icmp_with_data;
  sr_icmp_t3_hdr_t* icmp3_hdr;
  uint32_t temp_ip;
  uint8_t* to_send;
  struct sr_arpreq *arp_req;
  struct sr_if* iface;
  uint16_t checksum;
  struct sr_rt *rt;
  struct sr_arpentry *arp_entry;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* TODO - Done : Add forwarding logic here */

  e_hdr = (sr_ethernet_hdr_t *)packet;
  ether_type = ethertype(packet);

  if (ether_type == ethertype_arp) {
    /* TODO - Done
    handle arp 
    */
    arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* TODO - Done need to test
      handle request
      */

      /* make the arp */
      memcpy(&arp_reply, arp_hdr, sizeof(arp_reply));
      memcpy(arp_reply.ar_tha, arp_reply.ar_sha, ETHER_ADDR_LEN);
      memcpy(arp_reply.ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

      temp_ip = arp_reply.ar_tip;
      arp_reply.ar_tip = arp_reply.ar_sip;
      arp_reply.ar_sip = temp_ip;

      arp_reply.ar_op = ntohs(arp_op_reply);

      /* make the ether */
      memcpy(e_reply.ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
      memcpy(e_reply.ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      e_reply.ether_type = ntohs(ethertype_arp);

      /* send the reply */
      to_send = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      memcpy(to_send, &e_reply, sizeof(e_reply));
      memcpy(to_send+sizeof(e_reply), &arp_reply, sizeof(arp_reply));

      /* send */
      sr_send_packet(sr, to_send, sizeof(e_reply) + sizeof(arp_reply), interface);

      free(to_send);
    }
    else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      /* TODO - Done
      handle response 
      */
      arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      if (arp_req == NULL) {
        /* I guess we made an arp request for no reason? */
        /* but at least now its in the table */
      }
      else {
        while (arp_req->packets != NULL) {
          /* copy in the correct dest then send */
          memcpy(((sr_ethernet_hdr_t*)arp_req->packets->buf)->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, arp_req->packets->buf, arp_req->packets->len, arp_req->packets->iface);
          e_packet = arp_req->packets;
          arp_req->packets = e_packet->next;
          free(e_packet);
        }
      }
    }

    else {
      /* we got a weird ARP type so... */
      return;
    }

  }
  else if (ether_type == ethertype_ip) {
    /* TODO - Done
    handle ip
    */
    ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    memcpy(&ip_reply, ip_hdr, sizeof(ip_reply));

    /* check checksum */
    ip_reply.ip_sum = 0x00;
    ip_reply.ip_sum = (cksum((void*)&ip_reply, sizeof(ip_reply)));

    if (memcmp(&ip_reply, ip_hdr, sizeof(ip_reply))) {
      /* checksum failed so drop */
      return;
    } 

    if (ip_hdr->ip_len < 5) {
      /* failed min length */
      return;
    }


    iface = find_interface_by_ip(sr, ip_hdr->ip_dst);
    if (iface != NULL) {

      if (ip_protocol((uint8_t*)ip_hdr) == ip_protocol_icmp) {
        /* TODO - Done
        handle icmp
        */
        icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
        memcpy(&icmp_reply, icmp_hdr, sizeof(sr_icmp_hdr_t));

        /* check checksum */
        checksum = icmp_hdr->icmp_sum;
        icmp_with_data = (sr_icmp_hdr_t*)malloc(ip_hdr->ip_len - sizeof(sr_ip_hdr_t));
        memcpy(icmp_with_data, (uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t), ip_hdr->ip_len - sizeof(sr_ip_hdr_t));

        icmp_with_data->icmp_sum = 0;

        if (checksum != (cksum(icmp_with_data, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t)))) {
          /* failed checksum so free */
          free(icmp_with_data);
          return;
        }
        free(icmp_with_data);

        if ((icmp_hdr->icmp_type) == 8) {
          /* Echo case */
          to_send = (uint8_t*)malloc(len);
          memcpy(to_send, packet, len);

          /* ethernet part */
          e_hdr = (sr_ethernet_hdr_t*)to_send;
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

          /* ip part */
          ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = iface->ip;
          ip_hdr->ip_ttl = 64;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

          /* icmp part */
          icmp_hdr = (sr_icmp_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_code = 0;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, to_send, len, interface);
          free(to_send);
          return;

        }
        else {
          /* weird code so...? */
          return;
        }
      }
      else if (ip_protocol((uint8_t*)ip_hdr) == 6 || ip_protocol((uint8_t*)ip_hdr) == 17) {
        /* TODO - Done
        handle ip
        */
        to_send = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memcpy(to_send, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* ethernet part */
        e_hdr = (sr_ethernet_hdr_t*)to_send;
        memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

        /* ip part */
        ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = iface->ip;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* icmp part */
        icmp3_hdr = (sr_icmp_t3_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp3_hdr->icmp_type = 3;
        icmp3_hdr->icmp_code = 3;
        icmp3_hdr->icmp_sum = 0;
        memcpy(icmp3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
        icmp3_hdr->icmp_sum = cksum(icmp3_hdr, sizeof(sr_icmp_t3_hdr_t));

        sr_send_packet(sr, to_send, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
        free(to_send);
        return;
      }
      else {
        /* other code so... ? drop */
        return;
      }

    }
    else {
      /* not for me */
      if (ip_hdr->ip_ttl == 1) {
        /* TODO - Done send ICMP time exceeded */
        to_send = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memcpy(to_send, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* ethernet part */
        e_hdr = (sr_ethernet_hdr_t*)to_send;
        memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

        /* ip part */
        ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
        temp_ip = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = temp_ip;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* icmp part */
        icmp3_hdr = (sr_icmp_t3_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp3_hdr->icmp_type = 11;
        icmp3_hdr->icmp_code = 0;
        icmp3_hdr->icmp_sum = 0;
        memcpy(icmp3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
        icmp3_hdr->icmp_sum = cksum(icmp3_hdr, sizeof(sr_icmp_t3_hdr_t));

        sr_send_packet(sr, to_send, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
      }
      else {
        /* forward */
        to_send = (uint8_t*)malloc(len);
        memcpy(to_send, packet, len);

        ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
        rt = longestPrefixLookup(sr, ntohl(ip_hdr->ip_dst));
        if (rt == NULL) {
          /* failed to find any */
          /* free the old version */
          free(to_send);

          to_send = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(to_send, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          /* ethernet part */
          e_hdr = (sr_ethernet_hdr_t*)to_send;
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

          /* ip part */
          ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
          temp_ip = ip_hdr->ip_dst;
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = temp_ip;
          ip_hdr->ip_ttl = 64;
          ip_hdr->ip_p = ip_protocol_icmp;
          ip_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

          /* icmp part */
          icmp3_hdr = (sr_icmp_t3_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          icmp3_hdr->icmp_type = 3;
          icmp3_hdr->icmp_code = 0;
          icmp3_hdr->icmp_sum = 0;
          memcpy(icmp3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
          icmp3_hdr->icmp_sum = cksum(icmp3_hdr, sizeof(sr_icmp_t3_hdr_t));

          sr_send_packet(sr, to_send, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
          free(to_send);

        }
        else {
          /* need to forward */
          arp_entry = sr_arpcache_lookup(&sr->cache, rt->dest.s_addr);
          iface = sr_get_interface(sr, rt->interface);
          if (iface == NULL) {
            /* something went wrong weirdly */
            return;
          }
          e_hdr = (sr_ethernet_hdr_t*)to_send;
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          /* will fill in the entry later */

          /* ip part */
          ip_hdr = (sr_ip_hdr_t*)(to_send + sizeof(sr_ethernet_hdr_t));
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

          if (arp_entry) {
            /* we can forward right away */
            memcpy(e_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, to_send, len, iface->name);
            free(to_send);
            return;
          }
          else {
            /* we need to add it to the waitlist */
            sr_arpcache_queuereq(&sr->cache, rt->dest.s_addr, to_send, len, iface->name);
            return;
          }          
        }
      }        
    }

  }
  else {
    /* TODO - Done ?
    FAIL ...? */
  }
}/* -- sr_handlepacket -- */

