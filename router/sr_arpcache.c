#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"


void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    time_t now;
    time(&now);
    if(difftime(now, req->sent >= 1.0)){
        if(req->times_sent >= 5){
        /* Send icmp host unreachable to source addr of all pkts waiting on this request*/
            struct sr_packet *packets; 
            packets = req->packets; 
            while(packets){
                unsigned char *mac = (unsigned char *)((sr_ethernet_hdr_t *)(packets->buf))->ether_dhost;
                struct sr_if *iface = sr->if_list;
                while(iface){
                  if(memcmp(iface->addr, mac, ETHER_ADDR_LEN) == 0){
                    break;
                  }
                  iface = iface->next;
                }
                if(iface){
                    create_icmp_message(sr, packets->buf, packets->len, (uint8_t)3, (uint8_t)1); /*Sending ICMP message for destination host unreachable (type 3, code 1)*/
                }
                packets = packets->next;
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
        else{
            /*Send arp request*/
            struct sr_if* iface = sr_get_interface(sr, req->packets->iface);
            if(!iface) {
                fprintf(stderr, "Couldn't find interface");
                return;
            }
            uint8_t *new_req = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t *ethernet_header  = (sr_ethernet_hdr_t *)new_req;
            memset(ethernet_header->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
            sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(new_req + sizeof(sr_ethernet_hdr_t));
            memset(arp_header->ar_tha, 0x00, ETHER_ADDR_LEN);
            memcpy(arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
            ethernet_header->ether_type = htons(ethertype_arp);
            arp_header->ar_hrd = (unsigned short)htons(arp_hrd_ethernet);
            arp_header->ar_pro = (unsigned short)htons(ethertype_ip);
            arp_header->ar_hln = (unsigned char)ETHER_ADDR_LEN;
            arp_header->ar_pln = (unsigned char)sizeof(uint32_t);
            arp_header->ar_op = (unsigned short)htons(arp_op_request);
            arp_header->ar_sip = iface->ip;
            arp_header->ar_tip = req->ip;
            sr_send_packet(sr, new_req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
            free(new_req);
            req->sent = now;
            req->times_sent++;                  
        }
    }
}


void handle_arp_operations(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Minimum Length Sanity Check Failed");
        return;
    }
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned short ar_op = arp_header->ar_op;
    if(ntohs(ar_op) == arp_op_request){
        uint8_t *arp_request = malloc(len);
        memcpy(arp_request, packet, len);
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)arp_request;
        sr_arp_hdr_t *request_header = (sr_arp_hdr_t *)(arp_request + sizeof(sr_ethernet_hdr_t));
        memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
        struct sr_if *iface = sr_get_interface(sr, interface);
        memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
        memcpy(request_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
        memcpy(request_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        request_header->ar_op = htons(arp_op_reply);
        request_header->ar_sip = iface->ip;
        request_header->ar_tip = arp_header->ar_sip;
        handle_packet(sr, arp_request, len, iface, arp_header->ar_sip);
        free(arp_request);
    }
    else if(ntohs(ar_op) == arp_op_reply){
        struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
        if(req){
            struct sr_packet *packets = req->packets;
            while(packets){
                struct sr_if *iface = sr_get_interface(sr, packets->iface);
                if(iface){
                    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packets->buf;
                    memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
                    memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
                    sr_send_packet(sr, packets->buf, packets->len, packets->iface);
                }
                packets = packets->next;
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
	struct sr_arpreq* requests = sr->cache.requests;
    while(requests){ /*while there is a request*/
         struct sr_arpreq* next = requests->next; /*saving next as suggested in header*/
         handle_arpreq(sr, requests);
         requests = next;
    }
}

/* 
  This function is for sending packet to next hop if the destination ip is in cache or making an ARP request 
  it is not in the cache (that is done in the handle_arpreq function).
*/
void handle_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, uint32_t next_hop_ip){
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if(entry){ /*Entry is in cache*/
        /*using next_hop_ip->mac mapping in entry to send the packet*/
        /* Change destination and source mac address of packet*/
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
        memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, iface->name);
        free(entry);
    }
    else{
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, iface->name);
        handle_arpreq(sr, req);
    }
}


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

