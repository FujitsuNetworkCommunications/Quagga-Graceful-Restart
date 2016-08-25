#include <stdbool.h>
#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_gr.h"

#define MTYPE_OSPF_GR_IF 0

enum rsm {
  RSM_GrResInProgress = 1,
  RSM_GrResOK,
  RSM_GrResNOK,
  RSM_GrResMax,
};

#define GRACEFULE_RESTART_CONFIG "graceful_restart.conf"

#define Hlpr_Idle 0
#define Hlpr_InProgress 1
#define Hlpr_Completed 2

#define OSPF_RSM_SM_MONITOR_INTERVAL 10


enum ospf_gr_event {
  RSM_GrExtend,
  RSM_GrExpiry,
  RSM_GrIntAdjComplete,
  RSM_GrNbrInconsistent,
  RSM_GrNoNbr,
};

int gr_restart_rsn = GR_REASON_UNKNOWN;
int helper_enable = TRUE;

static char config_default[] = SYSCONFDIR GRACEFULE_RESTART_CONFIG;  

int
ospf_gr_get_restart_age (struct ospf *ospf)
{
  int age;

  if (ospf->gr_info.gr_status != OSPF_GR_NOT_RESTART) {
    if ((age = (ospf->gr_info.grace_period - 
                (tv_floor (tv_sub (recent_relative_time (), ospf->gr_info.start_time))))) > 0)
      return age;
  }
  return 0;
}

int
ospf_gr_get_helper_age (struct ospf_neighbor *nbr)
{
  int age;
  
  if (nbr->gr_helper.helper_status == OSPF_GR_HELPING) {
    if ((age = (nbr->gr_helper.grace_period - 
                (tv_floor (tv_sub (recent_relative_time (), nbr->gr_helper.start_time))))) > 0)
      return age;
  }
  return 0;
}

void
ospf_gr_init_helper_info (struct ospf_gr_nbr_info *helper_info)
{
  if (!helper_info) {
    zlog_warn ("Invalid Graceful Restart helper info."); 
    return;    
  } 
  
  helper_info->helper_status = OSPF_GR_NOT_HELPING;
  helper_info->start_time.tv_sec = 0;
  helper_info->start_time.tv_usec = 0;
  helper_info->helper_exit_rsn = OSPF_GR_NONE;
  helper_info->grace_period = 0;
  helper_info->t_adja_check = NULL;
}

void
ospf_gr_init_global_info (struct ospf* ospf)
{
  if (CHECK_FLAG (om->options, OSPF_GR_RESTART_IN_PROGRESS)) {
    ospf->gr_info.gr_enable = FALSE;
    ospf->gr_info.gr_status = OSPF_GR_PLANNED_RESTART;
    ospf->gr_info.start_time = recent_relative_time();
    ospf->gr_info.gr_exit_reason = OSPF_GR_IN_PROGRESS;
  } else {
    ospf->gr_info.gr_status = OSPF_GR_NOT_RESTART;
    ospf->gr_info.start_time.tv_sec = 0;
    ospf->gr_info.start_time.tv_usec = 0;
    ospf->gr_info.gr_exit_reason = OSPF_GR_NONE;
  }
  ospf->gr_info.gr_enable = FALSE;
  ospf->gr_info.grace_period = 0;
  ospf->gr_info.strict_lsa_check = FALSE;
  ospf->gr_info.gr_expiry_t = NULL;
}

static void
ospf_gr_parse_grace_lsa (struct lsa_header *lsah,
                         u_int32_t *grace_period,
                         struct in_addr *if_addr,
                         uint8_t *reason)
{
  struct ospf_grace_tlv_header *tlvh;
  struct ospf_grace_tlv_grace_period *grace_period_tlv;
  struct ospf_grace_tlv_restart_reason *grace_rst_rsn_tlv;
  struct ospf_grace_tlv_interface_addr *if_addr_tlv;
  u_int16_t sum, total;
  
  if (!lsah)
    return;
  
  sum = 0;
  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
  
  for (tlvh = OSPF_GRACE_TLV_HDR_TOP (lsah); sum < total;
       tlvh = OSPF_GRACE_TLV_HDR_NEXT (tlvh)) {
    
    sum += OSPF_GRACE_TLV_SIZE(tlvh);    
    
    switch (ntohs(tlvh->type)) {
    case OSPF_GRACE_TLV_GRACE_PERIOD:
      grace_period_tlv = (struct ospf_grace_tlv_grace_period*)tlvh;
      *grace_period = ntohl(grace_period_tlv->value);
      break;
    case OSPF_GRACE_TLV_RESTART_REASON:
      grace_rst_rsn_tlv = (struct ospf_grace_tlv_restart_reason*)tlvh;
      *reason = grace_rst_rsn_tlv->value;
      break;
    case OSPF_GRACE_TLV_INTERFACE_ADDR:
      if_addr_tlv = (struct ospf_grace_tlv_interface_addr*)tlvh;
      if_addr->s_addr = if_addr_tlv->value.s_addr;
      break;
    default:
      break;  
    }
  } 
  return;
}

static void
ospf_gr_build_grace_tlv_header (struct stream *s, struct ospf_grace_tlv_header *tlvh)
{
  stream_put (s, tlvh, sizeof (struct ospf_grace_tlv_header));
  return;
}

static void
ospf_gr_grace_period_tlv (struct stream *s, struct ospf_interface *oi)
{
  struct ospf_grace_tlv_grace_period grace_period;;
 
  memset(&grace_period, '\0', sizeof(struct ospf_grace_tlv_grace_period));
  
  grace_period.header.type = htons(OSPF_GRACE_TLV_GRACE_PERIOD); 
  grace_period.header.length = htons (sizeof (u_int32_t)); 
  grace_period.value = htonl(oi->ospf->gr_info.grace_period);
  
  ospf_gr_build_grace_tlv_header (s, &grace_period.header);
  stream_put (s, (&grace_period.header)+1, OSPF_GRACE_TLV_BODY_SIZE (&grace_period.header));
  return;
}

static void
ospf_gr_grace_restart_reason_tlv (struct stream *s, struct ospf_interface *oi)
{
  struct ospf_grace_tlv_restart_reason gr_reason;;   
 
  memset(&gr_reason, '\0', sizeof(struct ospf_grace_tlv_restart_reason));
  
  gr_reason.header.type = htons(OSPF_GRACE_TLV_RESTART_REASON); 
  gr_reason.header.length = htons(sizeof(char));  
  gr_reason.value = gr_restart_rsn;
  ospf_gr_build_grace_tlv_header (s, &gr_reason.header);
  stream_put (s, (&gr_reason.header)+1, OSPF_GRACE_TLV_BODY_SIZE (&gr_reason.header));
  return;
}

static void
ospf_gr_grace_if_addr_tlv (struct stream *s, struct ospf_interface *oi) 
{
  struct ospf_grace_tlv_interface_addr if_addr;
  struct prefix_ipv4 *prfx = (struct prefix_ipv4*)oi->address;
  
  if_addr.header.type = htons(OSPF_GRACE_TLV_INTERFACE_ADDR); 
  if_addr.header.length = htons (sizeof (struct in_addr)); 
  if_addr.value.s_addr = prfx->prefix.s_addr;
  
  ospf_gr_build_grace_tlv_header (s, &if_addr.header);
  stream_put (s, (&if_addr.header)+1, OSPF_GRACE_TLV_BODY_SIZE (&if_addr.header));
  return;
}

static void
ospf_gr_lsa_body_set (struct stream *s, struct ospf_interface *oi)
{
  ospf_gr_grace_period_tlv(s, oi);
  ospf_gr_grace_restart_reason_tlv(s, oi);
  ospf_gr_grace_if_addr_tlv(s, oi);
}

static struct ospf_lsa *
ospf_gr_lsa_new (struct ospf_area *area, struct ospf_interface *oi)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id;
  u_int32_t tmp;
  u_int16_t length;
  
  
  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL) {
    zlog_warn ("ospf_gr_lsa_new: stream_new() ?");
    goto out;
  }
  
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O;
  
  lsa_type = OSPF_OPAQUE_LINK_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRACE_LSA, 0);
  lsa_id.s_addr = htonl (tmp);
  
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_debug ("LSA[Type%d:%s]: Create an Opaque-LSA/Graceful Restart", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  ospf_gr_lsa_body_set(s, oi);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("ospf_gr_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("ospf_gr_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;

  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

 out:
  return new;
}

int
ospf_gr_lsa_originate (void *arg)
{
  struct ospf_lsa *new;
  struct ospf_area *area;
  struct ospf_interface *oi = (struct ospf_interface*)arg;
  int rc = -1;

  if (!CHECK_FLAG (om->options, OSPF_GR_SHUTDOWN_IN_PROGRESS) &&
      (oi->ospf->gr_info.gr_exit_reason == OSPF_GR_NONE)) {
    zlog_warn ("ospf_gr_lsa_originate: ospf grace shutdown not going");  
    goto out;
  } 
        
  if (!oi || (area = oi->area) == NULL)
    {
      zlog_warn ("ospf_gr_lsa_originate: Invalid argument?");
      goto out;
    }
  
  /* Create new Opaque-LSA/Graceful Resatart. */
  if ((new = ospf_gr_lsa_new (area, oi)) == NULL)
    {
      zlog_warn ("ospf_gr_lsa_originate: ospf_gr_lsa_new() ?");
      goto out;
    }

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  if (oi->ospf->gr_info.gr_exit_reason  != OSPF_GR_NONE) {
    new->data->ls_age = htons (OSPF_LSA_MAXAGE);
  }
  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, oi, new) == NULL)
    {
      zlog_warn ("ospf_gr_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }
  /* Flood new LSA through area. */
  ospf_flood_through_area(area, NULL, new);
        
  
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      char area_id[INET_ADDRSTRLEN];
      strcpy (area_id, inet_ntoa (area->area_id));
      zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/Graceful Restart: Area(%s)", new->data->type, inet_ntoa (new->data->id), area_id);
      ospf_lsa_header_dump (new->data);
    }


  rc = 0;
 out:
  return rc;
}

static void 
ospf_gr_event_handle (enum ospf_gr_event event, 
                      struct ospf_interface *oi)
{
  switch (event) {
  case RSM_GrExtend:
  case RSM_GrIntAdjComplete:
    oi->gr_state = RSM_GrResOK;
    break;
  case RSM_GrExpiry:
    oi->gr_state = RSM_GrResNOK;
    break;
  case RSM_GrNbrInconsistent:
    oi->ospf->gr_info.gr_exit_reason = OSPF_GR_TOPOLOGY_CHNAGE; /**/
    oi->gr_state = RSM_GrResNOK;
    break;
  case RSM_GrNoNbr:
    oi->gr_state = RSM_GrResNOK;
    break;
  default:
    break;
  } 
}
/*RFC 3623 Section 2.2 When to exit graceful restart 3)*/
static int
ospf_gr_grace_period_expiry (struct thread *t)
{
  struct ospf_interface *oif;  
  struct ospf *ospf = THREAD_ARG (t);
  struct listnode *node = NULL, *nnode = NULL; 
  
  for (ALL_LIST_ELEMENTS (ospf->oiflist, node, nnode, oif))
    ospf_gr_event_handle(RSM_GrExpiry, oif);
    
  ospf->gr_info.gr_exit_reason = OSPF_GR_TIMEOUT;
  return 0;
}

static void
ospf_gr_set_system_time (time_t store_time)
{
  struct timeval now;
  time_t curr;
  int rc = 0;

  curr = time(NULL);

  if (curr < store_time) {
    now.tv_sec = store_time;
    now.tv_usec = 0;
    rc=settimeofday(&now, NULL);
  }

  if (rc) {
    zlog_err("Failed to set system time in graceful restart");
  }
}

static void 
ospf_gr_read_state_info (void)
{
  FILE *gr_fp;
  int  graceful_enable = 0;
  long int sys_time = 0;

  gr_fp = fopen(config_default, "r");

  if (gr_fp == NULL) {
    zlog_info("%s: failed to open configuration file to read %s: %s\n",
              __func__, config_default, safe_strerror (errno));
    goto finished;
  }
 
  if(!feof(gr_fp)) {
    fscanf(gr_fp, "RESTARTTIME\t%ld\n", &sys_time); 
    ospf_gr_set_system_time((time_t)sys_time);
  } 

  if (!feof(gr_fp)) {
    fscanf(gr_fp, "GRACEFULEENABLE\t%d\n", &graceful_enable);
  }

  if (!feof(gr_fp)) {
    fscanf(gr_fp, "RESTARTRSN\t%d\n", &gr_restart_rsn);
  }
    
 finished:
  if (graceful_enable) {
    ospf_set_gr_restart();
  }
        
  if (gr_fp) {
    fclose(gr_fp);
    remove(config_default);     
  }

  return;

}

int
ospf_gr_is_going (void)
{
  if (CHECK_FLAG (om->options, OSPF_GR_RESTART_IN_PROGRESS)) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}
/*RFC 3623 section 2.3 Actions on exiting graceful restart */
static int 
ospf_gr_restart_exit_action(struct ospf *ospf)
{
  struct listnode *node = NULL, *nnode = NULL; 
  struct ospf_lsa *lsa;
  struct ospf_interface *oi;

  for (ALL_LIST_ELEMENTS (ospf->oiflist, node, nnode, oi)) {
    ospf_gr_lsa_originate(oi);
    ospf_router_lsa_update_area (oi->area);
    if(DR(oi).s_addr) {
      ospf_network_lsa_update (oi);
    } else {
      lsa = oi->network_lsa_self;
      if (lsa)
        ospf_lsa_flush_area (lsa, oi->area); 
    }
  }
  gr_restart_rsn = GR_REASON_UNKNOWN;
  return 0;

}

static int 
ospf_ins_restart_status(struct thread *t)
{
  struct ospf_master *m = THREAD_ARG (t);
  struct ospf *ospf ;
  struct listnode *node = NULL, *nnode = NULL; 

  m->restart_status_t = NULL; 
  for (ALL_LIST_ELEMENTS (m->ospf, node, nnode, ospf)) {
    if(ospf->gr_info.gr_exit_reason <= OSPF_GR_IN_PROGRESS)
      return 0;
  }

  ospf_unset_gr_restart();

  for (ALL_LIST_ELEMENTS (m->ospf, node, nnode, ospf)) {
    ospf_gr_restart_exit_action(ospf);
  }

  return 0;
}

static int
ospf_gr_restart_monitor (struct thread *t)
{
  struct ospf *ospf = THREAD_ARG (t);  
  struct ospf_interface *oif;
  int okcnt = 0, nokcnt = 0, cnt = 0;
  struct listnode *node = NULL, *nnode = NULL; 


  for (ALL_LIST_ELEMENTS (ospf->oiflist, node, nnode, oif)) {
    if(oif->gr_state == RSM_GrResNOK ) {
      nokcnt++;
    }
    if(oif->gr_state == RSM_GrResOK ) {
      okcnt++;
    }
    cnt++;
  }
  
  if (cnt == (nokcnt + okcnt)) 
    {
      ospf->gr_info.gr_status = OSPF_GR_NOT_RESTART;
      if (cnt == okcnt)
        {
          ospf->gr_info.gr_exit_reason = OSPF_GR_COMPLETED;
        }
      if(!(om->restart_status_t))
        om->restart_status_t =  thread_add_event(master, ospf_ins_restart_status, om, 0);
    } else {
    thread_add_timer (master, ospf_gr_restart_monitor,
                      ospf, OSPF_RSM_SM_MONITOR_INTERVAL);
  }
  return 0;
}

void
ospf_gr_write_state_info (int grace_enable)
{
  FILE *gr_fp;
  long int sys_time;
  
  time((time_t*)&sys_time);
  
  gr_fp = fopen(config_default, "w");

  if (gr_fp == NULL) {
    zlog_err ("%s: failed to open configuration file to write%s: %s\n",
              __func__, config_default, safe_strerror (errno));
    goto finished;
  }

  fprintf(gr_fp,"RESTARTTIME\t%ld\n", sys_time); /*TBD*/
  fprintf(gr_fp, "GRACEFULEENABLE\t%d\n", grace_enable);
  fprintf(gr_fp, "RESTARTRSN\t%d\n", gr_restart_rsn);
  fclose(gr_fp);

 finished:
  return;
}

static int
ospf_gr_no_nbr_monitor (struct thread *t)
{
  struct ospf_interface *oi = THREAD_ARG (t);

  if(!oi)
    return 0;

  if (oi->nbrs == NULL)
    {
      oi->gr_nonbr_monitor = NULL;
      ospf_gr_event_handle(RSM_GrNoNbr, oi);
    }
  return 0;
}

static void
ospf_gr_ism_change (struct ospf_interface *oi, int old_state)
{
  struct ospf *ospf;
  
  if(!oi)
    return;
 
  if(oi->ospf->gr_info.gr_status == OSPF_GR_NOT_RESTART)
    return;

  if(oi->gr_state >= RSM_GrResInProgress)
    return;
  
  switch (oi->state) {
  case ISM_PointToPoint:
  case ISM_DROther:
  case ISM_Waiting:
    oi->gr_state = RSM_GrResInProgress;
    oi->gr_nonbr_monitor = NULL;

    if (!(oi->ospf->gr_info.gr_monitor_t)) {
      ospf = oi->ospf;
      oi->ospf->gr_info.gr_monitor_t= thread_add_timer (master, ospf_gr_restart_monitor,
                                                        ospf, OSPF_RSM_SM_MONITOR_INTERVAL);
    }

    if(!(oi->gr_nonbr_monitor)) {
      oi->gr_nonbr_monitor = thread_add_timer (master, ospf_gr_no_nbr_monitor,
                                               oi, 2*(OSPF_IF_PARAM (oi, v_wait)));
    }
    break;
  case ISM_Down:
    if(oi->gr_state == RSM_GrResInProgress)
      //post GR_RES_NOK
      break;
  default:
    break;
  }
  return;
}

int 
ospf_gr_helping_nbr_count (struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;  
  struct route_node *rn;
  int nbr_cnt = 0;

  if (!oi) {
    zlog_warn("Invalid Interface\n");  
    return -1;  
  }
  
  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn)) {
    nbr = (struct ospf_neighbor *)rn->info; 
    if (nbr) {
      if (nbr->gr_helper.helper_status == OSPF_GR_HELPING)  
        nbr_cnt++;
    }
  }
  return nbr_cnt;
}

int
ospf_gr_chk_helping (struct ospf_neighbor *nbr)
{
  if(!nbr)
    return FALSE; 
  
  if (nbr->gr_helper.helper_status == OSPF_GR_HELPING)
    return TRUE;
  else
    return FALSE;                 
  
} 

static int
ospf_gr_examine_network_lsa (struct ospf_neighbor *nbr)
{
  int cnt = 0, match_found = 0, match_count = 0;
  
  struct ospf_lsa *lsa;
  struct route_node *rn;
  struct network_lsa *nlsa;
  struct in_addr *routers_id;
  
  if (!nbr)
    return 0;
  
  LSDB_LOOP (NETWORK_LSDB (nbr->oi->area), rn, lsa)
    {
      nlsa = (struct network_lsa *) lsa;
      
      if((IPV4_ADDR_SAME (&nlsa->header.id, &nbr->oi->ospf->router_id))) {
        routers_id = &nlsa->routers[0];
        while(routers_id) {
          cnt++;
          for (rn = route_top (nbr->oi->nbrs); rn; rn = route_next (rn)) {
            if((IPV4_ADDR_SAME (routers_id, &((struct ospf_neighbor *)rn->info)->router_id.s_addr))) {
              match_count++;
            }
            if(IPV4_ADDR_SAME (routers_id, &nbr->router_id)) {
              match_found = 1;
            }
          }
          routers_id++;
        }
        if(cnt == match_count) {
          return OSPF_GR_ADJ_OK;
        }
        
        if (!match_found) {
          return OSPF_GR_ADJ_NOK;
        }
      }
    }
  return OSPF_GR_ADJ_INPRGRESS;
}

static int
check_adj_pre_restart_router_lsa (struct ospf_neighbor *nbr)
{
  int i;
  struct router_lsa *rlsa;
  
  rlsa = (struct router_lsa*)nbr->oi->area->router_lsa_self;
  for(i=0; i < rlsa->links; i++) {
    if(rlsa->link[i].type == LSA_LINK_TYPE_POINTOPOINT) {
      if((IPV4_ADDR_SAME (&rlsa->link[i].link_id, &nbr->router_id)))
        return OSPF_GR_ADJ_OK;
    }
  }
  
  return OSPF_GR_ADJ_NOK;
}


static int
ospf_gr_examine_router_lsa(struct ospf_neighbor *nbr)
{
  int i;
  struct ospf_lsa *lsa;
  struct route_node *rn;
  struct router_lsa *rlsa;
  
  LSDB_LOOP (ROUTER_LSDB (nbr->oi->area), rn, lsa) {
    rlsa = (struct router_lsa *) lsa;
    
    if((IPV4_ADDR_SAME (&rlsa->header.adv_router, &nbr->router_id))) {
      for(i=0; i < rlsa->links; i++) {
        if(rlsa->link[i].type == LSA_LINK_TYPE_POINTOPOINT) {
          if((IPV4_ADDR_SAME (&rlsa->link[i].link_id, &nbr->oi->ospf->router_id))) {
            //adv_router should be there in in link type 1 of self originated lsa.
            return check_adj_pre_restart_router_lsa(nbr);
          }
        } else if (rlsa->link[i].type == LSA_LINK_TYPE_TRANSIT && 
                   IPV4_ADDR_SAME (&rlsa->link[i].link_data, &nbr->address.u.prefix4)) {
          if((IPV4_ADDR_SAME (&rlsa->link[i].link_id, &(DR (nbr->oi))))) {
            return OSPF_GR_ADJ_OK;
          } else {
            return OSPF_GR_ADJ_NOK; 
          }
        }
      }
    }
  }

  return OSPF_GR_ADJ_OK;
}
/*RFC 3623 Section 2.2 When to exit graceful restart 1) and 2)*/
static int
ospf_gr_adjacency_consistency_check (struct thread *t)
{
  struct ospf_neighbor *nbr = THREAD_ARG(t);
  struct ospf_interface *oi;
  int ret = OSPF_GR_ADJ_OK;

  if(!nbr)
    return 0;

  oi = nbr->oi; 
  /*Restarting router is DR in the oi*/

  if(IPV4_ADDR_SAME (&(DR(nbr->oi)), &(nbr->oi->address->u.prefix4))) {

    if (nbr->oi->area->router_lsa_self == NULL) {
      ospf_gr_event_handle(RSM_GrNbrInconsistent, (nbr->oi));
      return 0;
    }

    if (OSPF_GR_ADJ_OK == ospf_gr_examine_router_lsa(nbr)) {
      ret = ospf_gr_examine_network_lsa(nbr);

      if(OSPF_GR_ADJ_NOK == ret) {
        ospf_gr_event_handle(RSM_GrNbrInconsistent, oi);
        return 0;
      } else if(OSPF_GR_ADJ_OK == ret) {
        ospf_gr_event_handle(RSM_GrIntAdjComplete, oi);
        return 0;
      }
    }
  } else {
    if (OSPF_GR_ADJ_OK == ospf_gr_examine_router_lsa(nbr)) {
      ospf_gr_event_handle(RSM_GrIntAdjComplete, oi);
    } else {
      ospf_gr_event_handle(RSM_GrNbrInconsistent, oi);
    }
  }
  return 0;
}

static void
ospf_gr_nsm_change (struct ospf_neighbor *nbr, int old_state)
{
  if(!nbr) {
    return;
  }
  switch(nbr->state) {
  case NSM_Full: 
    if(nbr->oi->ospf->gr_info.gr_status != OSPF_GR_NOT_RESTART)
      nbr->gr_helper.t_adja_check = thread_add_event (master, ospf_gr_adjacency_consistency_check,                         
                                                      nbr, 0);
    break;
  default:
    break;
  } 
  return;
}

static int
ospf_gr_ls_retransmit_isrefresh(struct ospf_neighbor *nbr)
{
  int i;

  for(i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
    if ((ospf_lsdb_count (&nbr->ls_rxmt, i)) != (ospf_lsdb_count_self (&nbr->ls_rxmt, i))) {
      return TRUE;  
    }
  }
  return FALSE;
}
/*RFC 3623 section 3.2 Actions on exiting helper mode */
static int
ospf_gr_helper_exit_action (struct ospf_neighbor *nbr)
{
  if(!nbr)
    return 0;

  if(nbr->gr_helper.helper_t)
    {
      thread_cancel(nbr->gr_helper.helper_t);
      nbr->gr_helper.helper_t = NULL;
    }
  nbr->gr_helper.helper_status = OSPF_GR_NOT_HELPING;
  nbr->gr_helper.grace_period = 0;

  if((nbr->gr_helper.helper_exit_rsn == OSPF_GR_TIMEOUT) ||
     (nbr->gr_helper.helper_exit_rsn == OSPF_GR_TOPOLOGY_CHNAGE)) {
    OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_InactivityTimer);
  }
  else {
    OSPF_ISM_EVENT_EXECUTE (nbr->oi, ISM_NeighborChange);
  }
  ospf_router_lsa_update_area (nbr->oi->area);
  if(DR(nbr->oi).s_addr) {
    ospf_network_lsa_update (nbr->oi);
  } 

  return 0;
}

static int
ospf_adjacency_grace_period (struct thread *t)
{
  struct ospf_neighbor *nbr = THREAD_ARG(t);
  nbr->gr_helper.helper_exit_rsn = OSPF_GR_TIMEOUT;
  nbr->gr_helper.helper_t = NULL;

  ospf_gr_helper_exit_action(nbr);  

  return 0; 
}

/*RFC 3623 section 3.1 Entering Helper mode*/
int
ospf_gr_hlpr_new_lsa (struct ospf_lsa *lsa)
{ 
  u_int32_t grace_period;
  struct in_addr if_addr;
  uint8_t reason;
  struct ospf_neighbor *nbr;  
  struct lsa_header *lsah;    

  if (helper_enable == FALSE) {
    zlog_warn ("ospf_hlpr_new_lsa: OSPF Graceful Restart Helper not enable\n");
    return 0;
  }

  if (!lsa || !lsa->data) {
    zlog_err ("ospf_hlpr_new_lsa: Invalid LSA\n");
    return -1;
  }
  
  lsah = (struct lsa_header *) lsa->data;
  
  if (lsah->type != OSPF_OPAQUE_LINK_LSA) { 
    zlog_warn ("ospf_hlpr_new_lsa:LSA type %s \n", ospf_link_state_id_type_msg[lsah->type].str);
    return 0;
  }
  
  if (GET_OPAQUE_TYPE (ntohl (lsah->id.s_addr)) != OPAQUE_TYPE_GRACE_LSA) {
    zlog_warn ("ospf_hlpr_new_lsa: Invalid opaque LSA\n");
    return 0;
  }

  ospf_gr_parse_grace_lsa(lsah, &grace_period,
                          &if_addr, &reason);
  zlog_debug ("ospf_hlpr_new_lsa: Received LSA Grace Period %u, Interface address %s, Reason %u\n", 
              grace_period, inet_ntoa(if_addr), reason);
         
  nbr = ospf_nbr_lookup_by_addr(lsa->oi->nbrs, &if_addr); 
  if (!nbr){ 
    zlog_warn ("ospf_hlpr_new_lsa: Failed to find neigbor\n");
    return 0;
  }
  
  if (nbr->gr_helper.helper_status == OSPF_GR_HELPING) {
    zlog_warn ("ospf_hlpr_new_lsa: Helping is in progress\n");
    return 0;
  }
  

  if(!(LS_AGE(lsa) < (int32_t)grace_period)) {
    zlog_warn ("ospf_hlpr_new_lsa: Recieved LSA expired\n");
    return 0;
  }

  if (nbr->state != NSM_Full) {
    zlog_warn ("ospf_hlpr_new_lsa: Neighbor not in full state\n");
    return 0;
  }

  if (ospf_gr_ls_retransmit_isrefresh(nbr)) {
    zlog_warn ("ospf_hlpr_new_lsa: Network become inconsistent\n");
    return 0;
  }

  OSPF_NSM_TIMER_OFF (nbr->t_inactivity);
 
  nbr->gr_helper.helper_status = OSPF_GR_HELPING;
  nbr->gr_helper.grace_period = grace_period;
  nbr->gr_helper.helper_exit_rsn = OSPF_GR_IN_PROGRESS;
  nbr->gr_helper.start_time = recent_relative_time ();
  nbr->gr_helper.helper_t = thread_add_timer (master, ospf_adjacency_grace_period,
                                              nbr, grace_period );

  return 0; 
}

/*RFC 3623 Section 3.2  Exiting Helper mode*/
int
ospf_gr_hlpr_del_lsa (struct ospf_lsa *lsa)
{
  u_int32_t grace_period;
  struct in_addr if_addr;
  uint8_t reason;
  struct ospf_neighbor *nbr;  
  struct lsa_header *lsah;    

  if (!lsa || !lsa->data)
    return 0;
  
  lsah = (struct lsa_header *) lsa->data;
  
  if (lsah->type != OSPF_OPAQUE_LINK_LSA) 
    return 0;
  
  if (GET_OPAQUE_TYPE (ntohl (lsah->id.s_addr)) != OPAQUE_TYPE_GRACE_LSA)
    return 0;

  ospf_gr_parse_grace_lsa(lsah, &grace_period,
                          &if_addr, &reason);
  nbr = ospf_nbr_lookup_by_addr (lsa->oi->nbrs, &if_addr);  

  if(nbr->gr_helper.helper_status == OSPF_GR_HELPING)
    {
      ospf_gr_helper_exit_action(nbr);
      nbr->gr_helper.helper_exit_rsn = OSPF_GR_COMPLETED;
    }
  return 0;
}
/*RFC 3623 sction 3.1 Exiting Helper mode  
  3) A change in link-state database contents indicates a network
  topology change, which forces termination of a graceful
  restart.*/
int
ospf_gr_check_topology_change (struct ospf_lsa *curr_lsa,
                               struct ospf_lsa *new_lsa,
                               struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;
  struct route_node *rn;
  struct ospf *ospf;
  struct ospf_interface *oif;
  struct listnode *node, *nnode;
  int gr_exit = 0;
     
  if((!oi) || (!new_lsa)) {
    return 0;
  }

  ospf = oi->ospf;
 
  if(!ospf)
    return 0;

  if ((helper_enable == FALSE) || 
      (ospf->gr_info.gr_status != OSPF_GR_NOT_RESTART) || 
      (ospf->gr_info.strict_lsa_check == FALSE)) {
    zlog_warn ("ospf_gr_check_topology_change: OSPF Graceful Restart Helper/Strict LSA Check not enabled.\n");
    return 0;
  }
    
  if((new_lsa->data->type < OSPF_ROUTER_LSA) || 
     (new_lsa->data->type > OSPF_AS_NSSA_LSA)) {
    return 0;
  }

  if(!(curr_lsa))
    {
      gr_exit = 1;
    }
  if((curr_lsa) && (new_lsa))
    {
      if(ospf_lsa_different(curr_lsa, new_lsa)) {
        gr_exit = 1;
      }
    } 

  if(gr_exit) {     
    for (ALL_LIST_ELEMENTS (ospf->oiflist, node, nnode, oif)) {
      for (rn = route_top (oif->nbrs); rn; rn = route_next (rn)) {
        nbr = (struct ospf_neighbor *)rn->info; 
        if(nbr) {
          if(nbr->gr_helper.helper_status == OSPF_GR_HELPING) { 
            nbr->gr_helper.helper_exit_rsn = OSPF_GR_TOPOLOGY_CHNAGE;
            ospf_gr_helper_exit_action(nbr); 
          }
        }
      }
    }
  }
  return 0;
}

int
ospf_gr_init (void)
{
  int rc;

  rc = ospf_register_opaque_functab (
                                     OSPF_OPAQUE_LINK_LSA,
                                     OPAQUE_TYPE_GRACE_LSA,
                                     NULL,
                                     NULL,
                                     ospf_gr_ism_change, /*ospf graceful restart ism change
                                                           hook*/
                                     ospf_gr_nsm_change,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL);

  if (rc != 0)
    {
      zlog_warn ("ospf_gr_init: Failed to register functions");
      goto out;
    }
  ospf_gr_read_state_info();
  helper_enable = TRUE;
 out:
  return rc;
 
}

void
ospf_chk_restart (struct ospf* ospf)
{
  if(!ospf)
    return;
  if((ospf->gr_info.gr_enable == TRUE) &&
     (ospf->gr_info.grace_period > 0) && 
     (ospf->gr_info.gr_status == OSPF_GR_PLANNED_RESTART) && 
     (ospf->gr_info.gr_exit_reason ==  OSPF_GR_IN_PROGRESS) && 
     (ospf->gr_info.gr_expiry_t == NULL)) {
    ospf->gr_info.gr_expiry_t = thread_add_timer (master, ospf_gr_grace_period_expiry, 
                                                  ospf, ospf->gr_info.grace_period);
    zlog_debug("Graceful Restart Expiry task is created\n");
  }

}
