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

void create_icmp_message(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code) {
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_rt *dest = longest_prefix_match(sr, ip_header->ip_src);
    if(!dest) {
        fprintf(stderr, "No destination found in routing table");
        return;
    }
    struct sr_if* interface = sr_get_interface(sr, dest->interface);
    switch(type) {
        case (uint8_t)0: {
          memset(ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
          memset(ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);
          /*Swap Source and Destination and send back for echoing*/
          uint32_t swap = ip_header->ip_src;
          ip_header->ip_src = ip_header->ip_dst;
          ip_header->ip_dst = swap;
          sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          icmp_header->icmp_type = type;
          icmp_header->icmp_code = code;
          icmp_header->icmp_sum = 0;
          icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
          handle_packet(sr, packet, len, interface, dest->gw.s_addr);
          break;
        }
        /*Type 3 and Type 11: Time exceeded, destination host unreachable etc.*/
        case (uint8_t)11:
        case (uint8_t)3: {
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *icmp_packet = malloc(new_len);
            /*Ethernet header for icmp message*/
            sr_ethernet_hdr_t *icmp_ethernet_header = (sr_ethernet_hdr_t*)icmp_packet;
            memset(icmp_ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);
            memset(icmp_ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
            icmp_ethernet_header->ether_type = htons(ethertype_ip);
            /*IP header for icmp message*/
            sr_ip_hdr_t* icmp_ip_header = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
            icmp_ip_header->ip_v = 4;
            icmp_ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
            icmp_ip_header->ip_tos = 0;
            icmp_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            icmp_ip_header->ip_id = htons(0);
            icmp_ip_header->ip_off = htons(IP_DF);
            icmp_ip_header->ip_ttl = 255;
            icmp_ip_header->ip_p = ip_protocol_icmp;
            if(code == (uint8_t)3){
              icmp_ip_header->ip_src = ip_header->ip_dst;  
            }
            else{
              icmp_ip_header->ip_src =  interface->ip;
            }
            /*ICMP header, offset by ethernet and ip headers for message*/
            sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + (ip_header->ip_hl * 4));
            icmp_ip_header->ip_dst = ip_header->ip_src;
            icmp_ip_header->ip_sum = 0;
            icmp_ip_header->ip_sum = cksum(icmp_ip_header, sizeof(sr_ip_hdr_t));
            icmp_header->icmp_type = type;
            icmp_header->icmp_code = code;
            icmp_header->unused = 0;
            icmp_header->next_mtu = 0;
            memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);
            icmp_header->icmp_sum = 0;
            icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
            handle_packet(sr, icmp_packet, new_len, interface, dest->gw.s_addr);
            free(icmp_packet);
            break;
        }
    }
}

struct sr_rt* longest_prefix_match(struct sr_instance *sr, uint32_t ip) {
  struct sr_rt* rt_entry = NULL;
  struct sr_rt* curr_entry = sr->routing_table;
  while(curr_entry) {
      if((ip & curr_entry->mask.s_addr) == (curr_entry->dest.s_addr & curr_entry->mask.s_addr)) { /*Check for match*/
          if(!rt_entry || curr_entry->mask.s_addr > rt_entry->mask.s_addr) { /*Take largest match*/
              rt_entry = curr_entry;
          }
      }
      curr_entry = curr_entry->next;
  }
  return rt_entry;
}

/*Function to sanity check the incoming packets*/
int sanity_check(sr_ip_hdr_t *ip_header) {
  int min_length = 20;
  uint16_t checksum_received = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t checksum = cksum(ip_header, ip_header->ip_hl * 4);
  ip_header->ip_sum = checksum_received;
  if(checksum != checksum_received) {
    fprintf(stderr, "Checksum Invalid");
    return -1;
  }
  if(ip_header->ip_len < min_length) {
    fprintf(stderr, "IP Packet does not mean minimum length");
    return -1;  
  }
  return 0;
}
/*Function to sanity check the icmp messages received*/
int icmp_sanity_check(uint8_t *packet, unsigned int len) {
  uint8_t *ip_location = (packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)ip_location;
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_header->ip_hl * 4)) {
    fprintf(stderr, "ICMP Packet does not mean minimum length");
    return -1;
  }
  sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t checksum_received = icmp_header->icmp_sum;
  icmp_header->icmp_sum = 0;
  uint16_t checksum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
  icmp_header->icmp_sum = checksum_received;
  if(checksum != checksum_received) {
    fprintf(stderr, "Checksum Invalid");
    return -1;
  }

  return 0;
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
  if (ethertype(packet) == ethertype_arp){ /*ARP packet received*/
    if (sizeof(sr_ethernet_hdr_t) > len){
      fprintf(stderr, "Does not meet minimum length requirement");
      return;
    }
    handle_arp_operations(sr, packet, len, interface);
  }
  else if(ethertype(packet) == ethertype_ip){ /*IP packet received*/
    uint8_t *packet_content = packet + sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)packet_content;
    if(sanity_check(ip_header) < 0){
      return;
    }
    struct sr_if *iface = sr->if_list;
    while(iface){ /*Finding interface for corresponding destination IP*/
      if(iface->ip == ip_header->ip_dst){
        break;
      }
      iface = iface->next;
    }
    if (iface){ 
      if(ip_header->ip_p == ip_protocol_icmp){ /*If the packet is an ICMP message*/
          if(icmp_sanity_check(packet, len) < 0) {
            return;
          }
          sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if(icmp_header->icmp_type == (uint8_t)8) { /*If it is an echo*/
              create_icmp_message(sr, packet, len, (uint8_t)0, (uint8_t)0);
          }
      }
      else if(ip_header->ip_p == 0x0006 || ip_header->ip_p == 0x0011){ /*Checking for TCP and UDP*/
        create_icmp_message(sr, packet, len, (uint8_t)3, (uint8_t)3);
      }
    }
    else{
      sr_ip_hdr_t* ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      ip_header->ip_ttl--; /*Reduce time to live by 1*/
      if(ip_header->ip_ttl <= 0) { /*Check if time to live is 0 and if it is send ICMP message*/
          create_icmp_message(sr, packet, len, (uint8_t)11, (uint8_t)0);
          return;
      }
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4); /*Recalculating checksum*/
      struct sr_rt* rt_match = longest_prefix_match(sr, ip_header->ip_dst); /*Checking for longest prefix match*/
      if(!rt_match) { /*No match found*/
          create_icmp_message(sr, packet, len, (uint8_t)3, (uint8_t)0); /*Destination net unreachable*/
          return;
      }
      struct sr_if *next_interface = sr_get_interface(sr, rt_match->interface); /*Finding interface for next hop*/
      if(!next_interface) { /*No interface found*/
          fprintf(stderr, "Could not find next interface");
          return;
      }
      handle_packet(sr, packet, len, next_interface, rt_match->gw.s_addr); /*Handle the packet (send to next hop) now that all checks are performed*/
    }
  }
}
