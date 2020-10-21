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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

} 

void create_icmp_message(struct sr_instance *sr, uint8_t *frame, unsigned int len, uint8_t type, uint8_t code){
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)frame;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(frame + sizeof(sr_ethernet_hdr_t));
    struct sr_rt* dest = longest_prefix_match(sr, ip_header->ip_src);
    if(!dest) {
        fprintf(stderr, "No destination found in routing table");
        return;
    }
    if(type == (uint8_t)8){
      struct sr_if* iface = sr_get_interface(sr, dest->interface);
      memset(ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
      memset(ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);
      /*Swap Source and Destination and send back for echoing*/
      uint32_t swap = ip_header->ip_src;
      ip_header->ip_src = ip_header->ip_dst;
      ip_header->ip_dst = swap;
      sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_header->icmp_type = type;
      icmp_header->icmp_code = code;
      icmp_header->icmp_sum = 0;
      icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
      handle_packet(sr, frame, len, iface, dest->gw.s_addr);
    }
    else if(type == (uint8_t)3 || type == (uint8_t)11){
      struct sr_if* iface = sr_get_interface(sr, dest->interface);
      unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *icmp_packet = malloc(icmp_len);
      sr_ethernet_hdr_t *icmp_ethernet_header = (sr_ethernet_hdr_t *)icmp_packet;
      memset(icmp_ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);
      memset(icmp_ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
      icmp_ethernet_header->ether_type = htons(ethertype_ip);
      sr_ip_hdr_t *icmp_ip_header = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
      icmp_ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
      icmp_ip_header->ip_v = 4;
      icmp_ip_header->ip_tos = 0;
      icmp_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      icmp_ip_header->ip_id = htons(0);
      icmp_ip_header->ip_off = htons(IP_DF);
      icmp_ip_header->ip_ttl = 255;
      icmp_ip_header->ip_p = ip_protocol_icmp;
      icmp_ip_header->ip_sum = 0;
      icmp_ip_header->ip_sum = cksum(icmp_ip_header, sizeof(sr_ip_hdr_t));
      if(code == (uint8_t)3){
        icmp_ip_header->ip_src = ip_header->ip_dst;
      }
      else{
        icmp_ip_header->ip_src = iface->ip;
      }
      icmp_ip_header->ip_dst = ip_header->ip_src;
      sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + (ip_header->ip_hl * 4));
      icmp_header->icmp_type = type;
      icmp_header->icmp_code = code;
      icmp_header->unused = 0;
      icmp_header->next_mtu = 0;
      memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);
      icmp_header->icmp_sum = 0;
      icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
      handle_packet(sr, icmp_packet, icmp_len, iface, dest->gw.s_addr);
      free(icmp_packet);
    }
}

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
  if (ethertype(packet) == ethertype_arp){
    /*TODo verification*/
    handle_arp_operations(sr, packet, len, interface);
  }
  else if(ethertype(packet) == ethertype_ip){
    /*TODo Verification*/
    uint8_t *packet_content = packet + sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)packet_content;
    struct sr_if *iface = sr->if_list;
    while(iface){
      if(iface->ip == ip_header->ip_dst){
        break;
      }
      iface = iface->next;
    }
    if (iface){
      if(ip_header->ip_p == ip_protocol_icmp){
          /*TODO: Verify ICMP*/
          sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if(icmp_header->icmp_type == (uint8_t)8) {
              create_icmp_message(sr, packet, len, (uint8_t)0, (uint8_t)0);
          }
      }
      else if(ip_header->ip_p == 0x0006 || ip_header->ip_p == 0x0011){
        create_icmp_message(sr, packet, len, (uint8_t)3, (uint8_t)3);
      }
    }
    else{
      sr_ip_hdr_t* ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      ip_header->ip_ttl--;
      if(ip_header->ip_ttl == 0) {
          create_icmp_message(sr, packet, len, (uint8_t)11, (uint8_t)0);
          return;
      }
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
      struct sr_rt* rt_match = longest_prefix_match(sr, ip_header->ip_dst);
      if(!rt_match) {
          create_icmp_message(sr, packet, len, (uint8_t)3, (uint8_t)0);
          return;
      }
      struct sr_if *next_interface = sr_get_interface(sr, rt_match->interface);
      if(!next_interface) {
          fprintf(stderr, "Could not find next interface");
          return;
      }
      handle_packet(sr, packet, len, next_interface, rt_match->gw.s_addr);
    }
  }

}

/*TODO:  Verification methods, updating headers, comments*/

struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip) {
  struct sr_rt* rt_entry = NULL;
  struct sr_rt* curr_entry = sr->routing_table;
  while(curr_entry) {
      if((ip & curr_entry->mask.s_addr) == (curr_entry->dest.s_addr & curr_entry->mask.s_addr)) {
          if(!rt_entry || curr_entry->mask.s_addr > rt_entry->mask.s_addr) {
              rt_entry = curr_entry;
          }
      }
      curr_entry = curr_entry->next;
  }
  return rt_entry;
}