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

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */
uint32_t longestPrefixLookup(struct sr_instance* sr, uint32_t ip) {
  struct sr_rt* rte = sr->routing_table;
  uint32_t last_mask = 0, so_far = 0;
  while (rte) {
    if (rte->mask->s_addr > last_mask && 
        ntohl(rte->mask->s_addr) ^ ntohl(ip) == 
        ntohl(rte->mask->s_addr) ^ ntohl(rte->dest->s_addr)) {
      last_mask = rte->mask->s_addr;
      so_far = rte->dest->s_addr;
    }
    rte = rte->next;
  }
  return so_far;
}



/* make and re-checksum an ip response */
void make_ip_resp(sr_ip_hdr_t* new_hdr, sr_ip_hdr_t* old_hdr) {

  memcpy(new_hdr, old_hdr, sizeof(sr_ip_hdr_t));
  new_hdr->ip_ttl--;
  /* copy over to data so that we can checksum */ 
  int data[(sizeof(sr_ip_hdr_t))-(sizeof(uint16_t))];
  memcpy(data, new_hdr,(sizeof(sr_ip_hdr_t)-2*(sizeof(uint32_t))-(sizeof(uint16_t))));
  memcpy(data+(sizeof(sr_ip_hdr_t))-2*(sizeof(uint32_t))-(sizeof(uint16_t)), 
         new_hdr+(sizeof(new_hdr)) - 2*(sizeof(uint32_t)), 2*(sizeof(uint32_t)));

  new_hdr->ip_sum = cksum(data, (sizeof(sr_ip_hdr_t))-(sizeof(uint16_t)));
}

/* make an icmp response of type type, code code */
void make_icmp_resp(sr_icmp_hdr_t* new_hdr, uint8_t type, uint8_t code) {
  /*TODO*/
  new_hdr->icmp_type = type;
  new_hdr->icmp_code = code;
  new_hdr->icmp_sum = cksum(new_hdr, 2*(sizeof(uint8_t)));
}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(0);
    sr_ethernet_hdr_t e_hdr;
    sr_icmp_hdr_t icmp_hdr;
    sr_ip_hdr_t ip_hdr;
    sr_ethernet_hdr_t* first_packet = (sr_ethernet_hdr_t*)req->packets;
    struct sr_if* interface = sr_get_interface(sr, ((struct sr_packet*)first_packet)->iface);;
    uint8_t* to_send;
    sr_arp_hdr_t arp_reply;


    if (difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
            /* TODO - Done need to test
            send icmp host unreachable
            */
            /* make the icmp part */
            make_icmp_resp(&icmp_hdr, 11, 0);

            /* make the ip part */
            make_ip_resp(&ip_hdr, (sr_ip_hdr_t*)((uint8_t *)(first_packet+sizeof(sr_ethernet_hdr_t))));
            ip_hdr.ip_dst = ip_hdr.ip_src;
            ip_hdr.ip_src = interface->ip;
            ip_hdr.ip_ttl = 65; /* 65 so that it gets decremented later */
            ip_hdr.ip_p = ip_protocol_icmp;
            ip_hdr.ip_len += sizeof(icmp_hdr);
            /* remake to recalculate the checksum */
            make_ip_resp(&ip_hdr, &ip_hdr); 

            /* make the ethernet part */
            memcpy(e_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
            memcpy(e_hdr.ether_dhost, first_packet->ether_shost, ETHER_ADDR_LEN);
            e_hdr.ether_type = ethertype_ip;

            /* copy them all over */
            to_send = (uint8_t*)malloc(sizeof(icmp_hdr) + sizeof(e_hdr) + sizeof(sr_ip_hdr_t));
            memcpy(to_send, &e_hdr, sizeof(e_hdr));
            memcpy(to_send+sizeof(e_hdr), &ip_hdr, sizeof(ip_hdr));
            memcpy(to_send+sizeof(e_hdr)+sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));

            /* send and cleanup */
            sr_send_packet(sr, to_send, sizeof(icmp_hdr) + sizeof(ip_hdr) + sizeof(e_hdr), ((struct sr_packet*)first_packet)->iface);
            free(to_send);
            sr_arpreq_destroy(&sr->cache, req);
        }
        else {
            /* TODO
            send arp request 
            */
            arp_reply.ar_hrd = ntohs(arp_hrd_ethernet);
            arp_reply.ar_pro = 2048;
            arp_reply.ar_hln = ETHER_ADDR_LEN;
            arp_reply.ar_pln = 4;
            arp_reply.ar_op = ntohs(arp_op_request);
            memcpy(arp_reply.ar_sha, interface->addr, ETHER_ADDR_LEN);
            arp_reply.ar_sip = interface->ip;
            memset(arp_reply.ar_tha, 0x00, ETHER_ADDR_LEN);
            arp_reply.ar_tip = req->ip;

            memset(e_hdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
            memcpy(e_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
            e_hdr.ether_type = ethertype_arp;

            to_send = (uint8_t*)malloc(sizeof(arp_reply) + sizeof(e_hdr));
            memcpy(to_send, &e_hdr, sizeof(e_hdr));
            memcpy(to_send + sizeof(e_hdr), &arp_reply, sizeof(arp_reply));
            sr_send_packet(sr, to_send, sizeof(arp_reply) + sizeof(e_hdr), interface->name);
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
  sr_icmp_hdr_t* icmp_hdr, icmp_reply;
  sr_icmp_t3_hdr_t* icmp3_hdr;
/*  unsigned char temp_eth[ETHER_ADDR_LEN];*/
  uint32_t temp_ip;
  uint8_t* to_send;
  struct sr_arpreq *arp_req;


  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n***********\n\n");
  printf("*** -> Received packet of length %d\n",len);
  printf("Received on %s\n", interface);
  print_hdrs(packet, len); 
  printf("\n***********\n\n");
  /* TODO: Add forwarding logic here */

  e_hdr = (sr_ethernet_hdr_t *)packet;
  ether_type = ethertype(packet);

  if (ether_type == ethertype_arp) {
    /* TODO
    handle arp 
    */
    printf("Received ARP\n");
    arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* TODO - mostly done need to test
      handle request
      */
      printf("Received ARP Request\n");
      /* TODO
      check that its mine 
      */
      if (arp_hdr->ar_tip != sr_get_interface(sr, interface)->ip) {
        /* not for me */
        printf("Received a message but not for this iface\n");
        return;
      }
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
      to_send = (uint8_t*)malloc(sizeof(e_reply) + sizeof(arp_reply));
      memcpy(to_send, &e_reply, sizeof(e_reply));
      memcpy(to_send+sizeof(e_reply), &arp_reply, sizeof(arp_reply));

      printf("Responding with\n");
      print_hdrs(to_send, sizeof(e_reply) + sizeof(arp_reply));
      /* send */
      sr_send_packet(sr, to_send, sizeof(e_reply) + sizeof(arp_reply), interface);

      free(to_send);
    }
    else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      /* TODO
      handle response 
      */
      printf("Received ARP Response\n");


      /* wil need this at some point */
      /* sr_arpcache_queuereq(&sr->cache, arp_reply->tip, to_send, 
                     sizeof(e_reply) + sizeof(arp_reply), interface); */
      arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      if (arp_req == NULL) {
        /* I guess we made an arp request for no reason? */
        /* but at least now its in the table */
      }
      else {
        while (arp_req->packets != NULL) {
          sr_send_packet(sr, arp_req->packets->buf, arp_req->packets->len, arp_req->packets->iface);
          e_packet = arp_req->packets;
          arp_req->packets = e_packet->next;
          free(e_packet);
        }
      }
    }

    else {
      printf("Weird ARP type %x\n", arp_hdr->ar_op);
    }

  }
  else if (ether_type == ethertype_ip) {
    /* TODO
    handle ip
    */
    printf("Received IP packet\n");
    ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    memcpy(&ip_reply, ip_hdr, sizeof(ip_reply));

    /* check checksum */
    ip_reply.ip_sum = 0x00;
    ip_reply.ip_sum = cksum((void*)&ip_reply, sizeof(ip_reply));
    if (memcmp(&ip_reply, ip_hdr, sizeof(ip_reply))) {
      /* checksum failed so drop */
      printf("Failed checksum\n");
      return;
    } 

    if (ip_hdr->ip_len < 5) {
      printf("Failed min length\n");
      return;
    }

    if (ntohl(ip_hdr->ip_dst) == ntohl(sr_get_interface(sr, interface)->ip)) {
      printf("This is for me\n");

      if (ip_protocol(packet) == ip_protocol_icmp) {
        /* TODO
        handle icmp
        */
        printf("Received ICMP for me\n");
        icmp_hdr = (sr_icmp_hdr_t*)(ip_hdr + sizeof(sr_ip_hdr_t));
        memcpy(&icmp_reply, icmp_hdr, sizeof(sr_icmp_hdr_t));

        /* check checksum */
        icmp_reply.icmp_sum = 0x00;
        icmp_reply.icmp_sum = cksum((void*)&icmp_reply, sizeof(sr_icmp_hdr_t));
        if (memcmp(&icmp_reply, icmp_hdr, sizeof(sr_icmp_hdr_t))) {
          printf("Failed checksum\n");
          return;
        }

        if (icmp_hdr->type == 8) {
          /* echo */
          icmp_reply.icmp_type = 0;
          icmp_reply.icmp_sum = cksum(&icmp_reply, sizeof(sr_icmp_hdr_t));
        }

      }
      else {
        /* TODO 
        handle ip
        */
        printf("Received other than ICMP\n");
      }

    }
    else {
      printf("This is not for me\n");
/*      print_addr_ip_int(ntohl(sr_get_interface(sr, interface)->ip));
      print_hdr_ip((uint8_t *)ip_hdr);
*/    
    

      if (ip_protocol(packet) == ip_protocol_icmp) {
        /* TODO
        handle icmp
        */
        printf("Received ICMP\n");
      }
      else {
        /* TODO 
        handle ip
        */
        printf("Received other than ICMP\n");
      }
    }
  }
  else {
    /* TODO
    FAIL 
    */
  }



  


 
  

}/* -- sr_handlepacket -- */

