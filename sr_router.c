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
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

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
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    /* Add initialization code here! */

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
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (ethertype(packet) == ethertype_ip) {
    printf("dealing with ip_packet\n");
    handle_ip_packet(sr, packet, len, interface);
  } else if (ethertype(packet) == ethertype_arp) {
    printf("dealing with arp_packet\n");
    handle_arp_packet(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    printf("Length is too short");
    return;
  }
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  ip_header->ip_sum = 0;
  if(!cksum(ip_header, ip_header->ip_hl)) {
    printf("Invalid IP header checksum");
    return ;
  }

  struct sr_if *headed_to_rt_interface = headed_to_interface(sr, ip_header->ip_dst);

  if (headed_to_rt_interface) {
    uint32_t curr_status = sr_obtain_interface_status(sr, headed_to_rt_interface->name);
    if (curr_status == 0) {
      send_icmp_packet(sr, packet, interface, 3, 0); 
      return;
    }
    struct sr_if *curr = sr->if_list;
    while (curr) {
      if (((curr->ip & curr->mask) == (ip_header->ip_dst & curr->mask)) && (curr->status == 0)) {
        send_icmp_packet(sr, packet, interface, 3, 0); 
        return;
      }
      curr = curr->next;
    }
  }

  if (headed_to_rt_interface || inet_addr("255.255.255.255") == ip_header->ip_dst) { 
    printf("The IP packet is for us\n");
    if (ip_header->ip_p == ip_protocol_udp) {
      printf("UDP Packet received\n");
      sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t *) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t));
      if (rip_packet->command == 1) { /*request */
        printf("Request RIP Packet\n");
        send_rip_update(sr);
      } else if (rip_packet->command == 2) { /*response*/
        printf("Response RIP Packet\n");
        update_route_table(sr, ip_header, rip_packet, interface);
      }  else {
        send_icmp_packet(sr, packet, interface, 3, 3);
        return;
      }
    } else if (ip_header->ip_p != ip_protocol_icmp) {
      printf("Not ICMP protocol\n");
      uint8_t icmp_type = 3;
      uint8_t icmp_code = 3;
      send_icmp_packet(sr, packet, interface, icmp_type, icmp_code); /* port unreachable */
      return;

    } else {
      if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
        printf("Receive an ICMP Echo request\n");
        uint8_t icmp_type = 0;
        uint8_t icmp_code = 0;
        send_icmp_packet(sr, packet, interface, icmp_type, icmp_code);
        return;
      } else {
        printf("This aint a proper Echo request\n");
        return;
      }
    }
  } else { 
    
    if(ip_header->ip_ttl <= 1) {
      send_icmp_packet(sr, packet, interface, 11, 0);
      return;
    }
    struct in_addr addr;
    addr.s_addr = ip_header->ip_dst;
    
    struct sr_rt * curr = sr_routing_table_prefix_match(sr, addr);
    
    if(!curr) { /* if there is no match in the routing table */
      printf("Host unreachable\n");
      send_icmp_packet(sr, packet, interface, 3, 0);
      return;
    }

    struct sr_if *new_interface = sr_get_interface(sr, curr->interface);
    memcpy(e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);

    struct sr_arpentry *arp_entry;
    if (curr->gw.s_addr == 0) {
      arp_entry = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst);
    } else {
      arp_entry = sr_arpcache_lookup(&(sr->cache), curr->gw.s_addr);
    }

    if (arp_entry) {
      memcpy(e_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      ip_header->ip_ttl -= 1;
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, packet, len, curr->interface);
      free(arp_entry);
      return;
    } else {
      struct sr_arpreq *queued_arp_req;
      if (curr->gw.s_addr == 0) {
        queued_arp_req = sr_arpcache_queuereq(&(sr->cache),ip_header->ip_dst, packet, len, curr->interface);
      } else {
        queued_arp_req = sr_arpcache_queuereq(&(sr->cache), curr->gw.s_addr, packet, len, curr->interface);
      }
      handle_arpreq(sr, queued_arp_req);
      return;
    }
  }
}


void send_icmp_packet(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code) {
  printf("Sending a ICMP message");
  size_t icmp_hdr_size = 0;
  if (type == 0) {
    icmp_hdr_size = 64;
  } else if (type == 11) {
    icmp_hdr_size = sizeof(sr_icmp_t11_hdr_t);
  } else if(type == 3) {
    icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);
  }

  unsigned int len_new = icmp_hdr_size + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t *packet_new = (uint8_t *) malloc(len_new);
  bzero(packet_new, len_new); /* rset header*/
  struct sr_if *new_interface = sr_get_interface(sr, interface);

  sr_ip_hdr_t *prev_ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet_new;
  sr_ethernet_hdr_t *ehdr_old = (sr_ethernet_hdr_t *) packet;

  sr_icmp_t0_hdr_t *icmp_hdr_old = (sr_icmp_t0_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_icmp_t11_hdr_t *icmp_t11_hdr = (sr_icmp_t11_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(ehdr->ether_dhost, ehdr_old->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, ehdr_old->ether_dhost, ETHER_ADDR_LEN);
  ehdr->ether_type = htons(ethertype_ip);
  
  ip_hdr->ip_v = prev_ip_hdr->ip_v; 
  ip_hdr->ip_hl = 5; /* 5 or 6 words */ 
  ip_hdr->ip_tos = prev_ip_hdr->ip_tos; 
  ip_hdr->ip_id = prev_ip_hdr->ip_id; 
  ip_hdr->ip_off = prev_ip_hdr->ip_off;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp; 
  ip_hdr->ip_src = new_interface->ip;
  ip_hdr->ip_dst = prev_ip_hdr->ip_src;
  /* 20 is the min ip header length */
  ip_hdr->ip_len = htons(icmp_hdr_size + 20);
  
  printf("length of hdr_size is: %zu", icmp_hdr_size);
  if (type == 0) {
    printf("Case 0");
    icmp_t0_hdr->icmp_code = code;
    icmp_t0_hdr->icmp_type = type;
    icmp_t0_hdr->identifier = icmp_hdr_old->identifier;
    icmp_t0_hdr->sequence_number = icmp_hdr_old->sequence_number;
    icmp_t0_hdr->timestamp = icmp_hdr_old->timestamp;
    /* hand-calculated the data size */
    memcpy(icmp_t0_hdr->data, icmp_hdr_old->data, 54);
    icmp_t0_hdr->icmp_sum = 0;
    icmp_t0_hdr->icmp_sum = cksum(icmp_t0_hdr, icmp_hdr_size);
      
  } else if (type == 11) {
    printf("Case 1");
    icmp_t11_hdr->icmp_code = code;
    icmp_t11_hdr->icmp_type = type;
    /*packet + sizeof(sr_ethernet_hdr_t)*/
    memcpy(icmp_t11_hdr->data, prev_ip_hdr, ICMP_DATA_SIZE);
    icmp_t11_hdr->icmp_sum = 0;
    icmp_t11_hdr->icmp_sum = cksum(icmp_t11_hdr, icmp_hdr_size);
  } else if(type == 3) {
    printf("Case 2");
    icmp_t3_hdr->icmp_code = code;
    icmp_t3_hdr->icmp_type = type;
    memcpy(icmp_t3_hdr->data, prev_ip_hdr, ICMP_DATA_SIZE);
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, icmp_hdr_size);
  }

  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* send now */
  sr_send_packet(sr, packet_new, len_new, interface);
  free(packet_new);
}

struct sr_rt* sr_routing_table_prefix_match(struct sr_instance* sr, struct in_addr addr) {
  struct sr_rt* cur = sr->routing_table;
  struct sr_rt* longest_entry = 0;
  unsigned long longest_len = 0;

  while(cur) {
    if (cur->metric < INFINITY) {
      if((cur->dest.s_addr & cur->mask.s_addr) == (addr.s_addr & cur->mask.s_addr)){
        if(longest_len < cur->mask.s_addr){
          longest_len = cur->mask.s_addr;
          longest_entry = cur;
        }
      }
    }
    cur=cur->next;
  }
  return longest_entry;
}

struct sr_if* headed_to_interface(struct sr_instance * sr, uint32_t ip_destination)
{
  struct sr_if* currInterface = sr->if_list;
  while (currInterface) 
  {
    if(ip_destination == currInterface->ip)
    {
      return currInterface;
    }
    currInterface = currInterface->next;
  }
  return 0;
}

void handle_arp_request(struct sr_instance* sr, sr_ethernet_hdr_t *eth_hdr, sr_arp_hdr_t *arp_hdr,
    struct sr_if* interface/* lent */){
  /*Insert into ARP cache*/
  sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

  /*Send reply*/
  if(arp_hdr->ar_tip == interface->ip){
    printf("ARP request target reached, sending reply...\n");
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(len);

    sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = ntohs(ethertype_arp);

    reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
    reply_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(reply_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = interface->ip;
    memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

    sr_send_packet(sr, packet, len, interface->name);
  }
}

void handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* interface/* lent */){
  /*Check if destination*/
  if(arp_hdr->ar_tip == interface->ip){
    printf("ARP reply target reached\n");
    struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    /*Go through requests waiting on reply*/
    if(request){
      struct sr_packet *curr = request->packets;
      while(curr){
        sr_ip_hdr_t *ip_hdr =
            (sr_ip_hdr_t *) (curr->buf + sizeof(sr_ethernet_hdr_t));
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) curr->buf;

        memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        sr_send_packet(sr, curr->buf, curr->len, interface->name);
        curr = curr->next;
      }

      sr_arpreq_destroy(&sr->cache, request);
    }
  }
}

void handle_arp_packet(struct sr_instance* sr, uint8_t * packet/* lent */,
    unsigned int len, char* interface/* lent */) {
  /*check length*/
  if (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
    printf("There was an error. The packet is too short.");
    return;
  }

  sr_arp_hdr_t *arp_hdr =
      (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
  struct sr_if* rcvd_interface = sr_get_interface(sr, interface);

  printf("ARP frame detected, processing...\n");

  /*look at opcode*/
  switch(ntohs(arp_hdr->ar_op)){
    case arp_op_request:
      printf("Handling ARP request...\n");
      handle_arp_request(sr, ethernet_hdr, arp_hdr, rcvd_interface);
      break;
    case arp_op_reply:
      printf("Handling ARP reply...\n");
      handle_arp_reply(sr, arp_hdr, rcvd_interface);
      break;
    default:
      printf("ARP frame not reply or request\n");
      return;
  }
}

