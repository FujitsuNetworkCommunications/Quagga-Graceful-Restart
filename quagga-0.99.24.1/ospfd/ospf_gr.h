#ifndef _ZEBRA_OSPF_GR_H
#include <sys/time.h>
#include <zebra.h>
#define _ZEBRA_OSPF_GR_H

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

struct ospf_lsa;
struct ospf;

enum ospf_gr_return_value {
  OSPF_GR_ADJ_NONE,
  OSPF_GR_ADJ_OK,
  OSPF_GR_ADJ_INPRGRESS,
  OSPF_GR_ADJ_NOK,
  OSPF_GR_ADJ_MAX,
};


struct ospf_grace_tlv_header
{
  u_int16_t type;    
  u_int16_t length;   /* Value portion only, in octets */
};

#define OSPF_GRACE_TLV_HDR_SIZE                 \
  (sizeof (struct ospf_grace_tlv_header))

/*
 * Following section defines TLV body parts.
 *  */

/* Grace Period TLV *//* Mandatory */
#define OSPF_GRACE_TLV_GRACE_PERIOD    1
struct ospf_grace_tlv_grace_period
{
  struct ospf_grace_tlv_header  header;   /* Value length is 4 octets. */
  u_int32_t  value;
};


/* Graceful restart reason TLV */  
#define OSPF_GRACE_TLV_RESTART_REASON    2
struct ospf_grace_tlv_restart_reason 
{
  struct ospf_grace_tlv_header  header;     /* Value length is 1 octets. */  
#define GR_REASON_UNKNOWN 0
#define GR_REASON_SOFTWARE_RESTART 1
#define GR_REASON_SOFTWARE_RELOAD 2
#define GR_REASON_SWTC_TO_REDUNDANT_CNTRL_PROCESSOR 3 
  u_char value;
};

/* IP interface address TLV */
#define OSPF_GRACE_TLV_INTERFACE_ADDR   3
struct ospf_grace_tlv_interface_addr 
{
  struct ospf_grace_tlv_header  header;   /* Value length is 4 octets. */
  struct in_addr value;  
};

#define OSPF_GRACE_TLV_HDR_SIZE                 \
  (sizeof (struct ospf_grace_tlv_header))

#define OSPF_GRACE_TLV_BODY_SIZE(tlvh)                          \
  (ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))

#define OSPF_GRACE_TLV_SIZE(tlvh)                               \
  (OSPF_GRACE_TLV_HDR_SIZE + OSPF_GRACE_TLV_BODY_SIZE(tlvh))

#define OSPF_GRACE_TLV_HDR_TOP(lsah)                                    \
  (struct ospf_grace_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)

#define OSPF_GRACE_TLV_HDR_NEXT(tlvh)                                   \
  (struct ospf_grace_tlv_header *)((char *)(tlvh) + OSPF_GRACE_TLV_SIZE(tlvh))

enum ospf_gr_support {
  OSPF_GR_SUPPORT_NONE = 1,
  OSPF_GR_SUPPORT_PLANNED = 2,
  OSPF_GR_SUPPORT_UNLANNED = 3,
};

enum ospf_gr_status {
  OSPF_GR_NOT_RESTART = 1,
  OSPF_GR_PLANNED_RESTART = 2,
  OSPF_GR_UNPLANNED_RESTART = 3,
};

enum ospf_gr_exit_reason {
  OSPF_GR_NONE = 1,
  OSPF_GR_IN_PROGRESS,
  OSPF_GR_COMPLETED,
  OSPF_GR_TIMEOUT,
  OSPF_GR_TOPOLOGY_CHNAGE,
};

enum ospf_gr_helpr_status {
  OSPF_GR_NOT_HELPING = 1,
  OSPF_GR_HELPING = 2,
};

struct ospf_gr_info {
  int helper_enable;
  int gr_enable;
  int32_t grace_period; 
  int strict_lsa_check;
  /*Graceful Restart status*/
  int gr_status;
  struct timeval start_time;
  int32_t gr_exit_reason;
  /*Monitors */
  struct thread *gr_monitor_t;
  struct thread *gr_expiry_t;
};

struct ospf_gr_nbr_info {
  uint8_t helper_status;  
  struct timeval start_time;
  uint8_t helper_exit_rsn;
  uint32_t grace_period;
  struct thread *helper_t;
  struct thread *t_adja_check;
};

extern struct ospf_gr_info global_gr_info;
extern int helper_enable;
extern  int gr_restart_rsn;
void
ospf_gr_write_state_info (int grace_enable);

int
ospf_gr_init (void);

void
ospf_gr_init_helper_info (struct ospf_gr_nbr_info *helper_info);

int
ospf_gr_hlpr_new_lsa (struct ospf_lsa *lsa);
int
ospf_gr_hlpr_del_lsa (struct ospf_lsa *lsa);
void
ospf_chk_restart (struct ospf* ospf);
void
ospf_gr_init_global_info (struct ospf* ospf);
int
ospf_gr_lsa_originate (void *arg);
#endif /*_ZEBRA_OSPF_GR_H*/
 
