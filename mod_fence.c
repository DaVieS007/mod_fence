/*
   Copyright 2016 Hlavaji Viktor / DaVieS
        nPulse.net / davies@npulse.net
    
    Thanks to Systech Global Ltd (systech.hu) to actively support this project


   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/* This module has only one primary task to covering apache with additional fences
    to protect against:

    - Hack (like: hostname: () {})
    - Unresponsible or very slow website (hitting F5 like shooting in Call Of Duty)
    - Also Good against many well known attacks like: slowloris
    - PHP/Session FLOCK() stucking
*/

#include "ap_release.h"
#if AP_SERVER_MAJORVERSION_NUMBER >= 2 && AP_SERVER_MINORVERSION_NUMBER >= 4
  #define DEF_IP   useragent_ip
  #define DEF_ADDR useragent_addr
  #define DEF_POOL pool
#else
  #define DEF_IP   connection->remote_ip
  #define DEF_ADDR connection->remote_addr
  #define DEF_POOL connection->pool
#endif

#define MAX_HOSTNAME_LEN 255 //https://tools.ietf.org/html/rfc3986

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_vhost.h"
#include "apr_strings.h"
#include "http_main.h"
#include "ap_mpm.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"
#include "http_log.h"

#define VERSION "mod_fence/0.9b"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"


#include <ctype.h> // isspace
#include <arpa/inet.h>

module AP_MODULE_DECLARE_DATA fence_module;
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

typedef struct {
    int                enable;
    int                timeout;
    int                softReqs;
    int                hardReqs;
} fence_server_cfg;

typedef struct {
    const char  *old_ip;
    request_rec *r;
} fence_cleanup_rec;


/** INIT_HANDLER **/
static int init_handler(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, s, "Loading version %s.", VERSION);
    ap_add_version_component(pconf, VERSION);

    return OK;
}
/** INIT_HANDLER **/


/** FENCE_CREATE_SERVER_CFG **/
static void *fence_create_server_cfg(apr_pool_t *p, server_rec *s) 
{
    fence_server_cfg *cfg = (fence_server_cfg *)apr_pcalloc(p, sizeof(fence_server_cfg));
    if (!cfg)
    {
        return NULL;
    }

    cfg->enable = 0;
    cfg->timeout = 0;
    cfg->softReqs = 0;
    cfg->hardReqs = 0;

    return (void *)cfg;
}
/** FENCE_CREATE_SERVER_CFG **/

/** FENCE_ENABLE **/
static const char *fence_enable(cmd_parms *cmd, void *dummy, int flag) 
{
    server_rec *s = cmd->server;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &fence_module);

    cfg->enable = flag;
    return NULL;
}
/** FENCE_ENABLE **/

/** FENCE_SETSOFTREQS **/
static const char *fence_setSoftReqs(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &fence_module);

    cfg->softReqs = atoi(arg);
    return NULL;

}
/** FENCE_SETSOFTREQS **/

/** FENCE_SETHARDREQS **/
static const char *fence_setHardReqs(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &fence_module);

    cfg->hardReqs = atoi(arg);
    return NULL;

}
/** FENCE_SETHARDREQS **/


/** FENCE_SETTIMTEOUT **/
static const char *fence_settimeout(cmd_parms *cmd, void *dummy, const char *arg) 
{
    server_rec *s = cmd->server;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &fence_module);

    cfg->timeout = atoi(arg);
    return NULL;
}
/** FENCE_SETTIMTEOUT **/

/** IS_HOSTNAME_VALID **/
char is_hostname_valid(const char *hostname)
{
  char ret = 1, found = 0;
  size_t i, i2, len, len2;

  char allowed_chars[] = "QWERTZUIOPASDFGHJKLYXCVBNMqwertzuiopasdfghjklyxcvbnm-_.0123456789:[]";

  len = strlen(hostname);
  len2 = strlen(allowed_chars);

  /** AVOID BUFFER OVERFLOW **/
  if(len > MAX_HOSTNAME_LEN)
  {
    return 0;
  }
  /** AVOID BUFFER OVERFLOW **/

  for(i = 0; i < len; i++)
  {
    found = 0;
    for(i2 = 0; i2 < len2; i2++)
    {
      if(hostname[i] == allowed_chars[i2])
      {
        found = 1;
      }
    }

    if(!found)
    {
      ret = 0;
      break;      
    }
  }

  return ret;
}
/** IS_HOSTNAME_VALID **/

/** FENCE_POST_READ_REQUEST **/
static int fence_post_read_request(request_rec *r) 
{
    char *fwdvalue, *val, *mask, *last_val;
    int i, j;
    apr_port_t tmpport;
    apr_pool_t *tmppool;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(r->server->module_config,
                                                                   &fence_module);
    if (!cfg->enable)
    {
        return DECLINED;
    }

    static int server_limit, thread_limit, threads_per_child, max_servers,
           is_async;
    
    static pid_t child_pid;
    worker_score *ws_record = apr_palloc(r->pool, sizeof *ws_record);
    process_score *ps_record;
    int hard_slot_used = 0;
    int soft_slot_used = 0;
    char invalid_hostname = 0;

    pid_t *pid_buffer, worker_pid;
    char *stat_buffer;
    char datebuff[APR_RFC822_DATE_LEN + 1];

    int *thread_idle_buffer = NULL;
    int *thread_busy_buffer = NULL;
    clock_t tu, ts, tcu, tcs;
    ap_generation_t mpm_generation, worker_generation;

    apr_time_t nowtime = apr_time_now();
    tu = ts = tcu = tcs = 0;
    time_t tst = 0;


    /** INIT **/
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads_per_child);
    /* work around buggy MPMs */
    if (threads_per_child == 0)
        threads_per_child = 1;
    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_servers);
    ap_mpm_query(AP_MPMQ_IS_ASYNC, &is_async);
    /** INIT **/

    pid_buffer = apr_palloc(r->pool, server_limit * sizeof(pid_t));
    stat_buffer = apr_palloc(r->pool, server_limit * thread_limit * sizeof(char));
    if (is_async) 
    {
        return DECLINED;
    }

    if(!is_hostname_valid(r->hostname))
    {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r, "[mod_fence] Invalid Hostname: %s",r->hostname);
        return 400; //No Fancy response, invalid hostname earns simple 400 ERROR..
    }


    /** ITERATE_CONNECTION_POOL **/
    for (i = 0; i < server_limit; ++i) 
    {
        for (j = 0; j < thread_limit; ++j) 
        {
            ap_copy_scoreboard_worker(ws_record, i, j);

            if (ws_record->access_count == 0 && (ws_record->status == SERVER_READY || ws_record->status == SERVER_DEAD)) 
            {
                continue;
            }

            ps_record = ap_get_scoreboard_process(i);

/*              Filter or not to be? - this is the question..
            if(!strcmp(r->DEF_IP,"127.0.0.1"))
            {
                continue; //DONT FILTER LOCALHOST
            }
*/
            if(cfg->softReqs && !strcmp(ws_record->client, r->DEF_IP) && ( ws_record->status == SERVER_BUSY_READ || ws_record->status == SERVER_BUSY_WRITE || ws_record->status == SERVER_GRACEFUL))
            {
                soft_slot_used++;
            }

            if(cfg->hardReqs && (long)apr_time_sec(nowtime - ws_record->last_used) > 0 && !strcmp(ws_record->client, r->DEF_IP) && ( ws_record->status == SERVER_BUSY_READ || ws_record->status == SERVER_BUSY_WRITE || ws_record->status == SERVER_GRACEFUL))
            {
                hard_slot_used++;
            }

            /**
                ap_rprintf(r,
                           " <i>%s {%s}</i> <i>(%s)</i> <b>[%s]</b><br />\n\n",
                           ap_escape_html(r->pool,
                                          ws_record->client),
                           ap_escape_html(r->pool,
                                          ap_escape_logitem(r->pool,
                                                            ws_record->request)),
                           ap_escape_html(r->pool,
                                          ws_record->protocol),
                           ap_escape_html(r->pool,
                                          ws_record->vhost));
            **/


            /** UNUSED FROM MOD_STATUS **/
            /*
            if (ws_record->start_time == 0L)
                req_time = 0L;
            else
                req_time = (long)
                    ((ws_record->stop_time - ws_record->start_time) / 1000);
            if (req_time < 0L)
                req_time = 0L;

            lres = ws_record->access_count;
            my_lres = ws_record->my_access_count;
            conn_lres = ws_record->conn_count;
            bytes = ws_record->bytes_served;
            my_bytes = ws_record->my_bytes_served;
            conn_bytes = ws_record->conn_bytes;
            */
            /** UNUSED FROM MOD_STATUS **/

            if (ws_record->pid) 
            { /* MPM sets per-worker pid and generation */
                worker_pid = ws_record->pid;
                worker_generation = ws_record->generation;
            }
            else 
            {
                worker_pid = ps_record->pid;
                worker_generation = ps_record->generation;
            }

            if((long)apr_time_sec(nowtime - ws_record->last_used) >= cfg->timeout && ( ws_record->status == SERVER_BUSY_READ || ws_record->status == SERVER_BUSY_WRITE || ws_record->status == SERVER_GRACEFUL))
            {
                if(ps_record->pid > 0)
                {
                    kill(ps_record->pid, SIGKILL);
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "[mod_fence] Stucked Child %d, Killed",ps_record->pid);
                }
            }

        } 
    }
    /** ITERATE_CONNECTION_POOL **/



    /** MITIGATE **/
    if(soft_slot_used > cfg->softReqs || hard_slot_used > cfg->hardReqs)
    {
        // GIVE some weird summary about mitigation to endusers

        ap_set_content_type(r, "text/html");

        ap_rputs("<html><head>"
        "<meta name='robots' content='NOINDEX, NOFOLLOW'>"
        "</meta><title>mod_fence / Request Terminated</title>"
        "<style>td { border: 1px solid gray; padding: 10px; } </style>"
        "</head>"
        "<body style='margin: 20px; padding: 20px; color: #333;'>"
        "<h1>Your request terminated due to Auto-Mitigation.</h1>"
        "<br /><br />"
        "You are reached maximum-allowed request limit at the same time and it's seems like non-usual activity.<br /><br />"
        "To protect the service you suffered mitigation on your connection rate.<br />"
        "Please refer the table below of your recent activity that seems currently abnormal<br /><br />"
        "In any other case please try again later or you can refresh by clicking <a href='' style='color: #333;'><b>here</b></a>.<br /><br />",r);

        /** SOME DETAILS **/
        ap_rputs("<table style='border: 1px solid gray; width: 80%;'>",r);
        /** ITERATE_CONNECTION_POOL **/
        for (i = 0; i < server_limit; ++i) 
        {
            for (j = 0; j < thread_limit; ++j) 
            {
                ap_copy_scoreboard_worker(ws_record, i, j);

                if (ws_record->access_count == 0 && (ws_record->status == SERVER_READY || ws_record->status == SERVER_DEAD)) 
                {
                    continue;
                }

                ps_record = ap_get_scoreboard_process(i);

                if(!strcmp(ws_record->client, r->DEF_IP) && (ws_record->status == SERVER_BUSY_READ || ws_record->status == SERVER_BUSY_WRITE))
                {
                    datebuff[0] = 0x00;
                    apr_rfc822_date(datebuff, ws_record->last_used);

                    ap_rputs("<tr>",r);
                    ap_rprintf(r, "<td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td>\n",
                    datebuff,
                    ap_escape_html(r->pool,ws_record->client),
                    ap_escape_html(r->pool,r->hostname),
                    ap_escape_html(r->pool,ap_escape_logitem(r->pool,ws_record->request)));

                    ap_rputs("</tr>",r);
                }
            }
        }
        ap_rputs("</table>",r);
        /** SOME DETAILS **/

        ap_rputs(ap_psignature("<br /><br /><hr>\n",r),r);
        ap_rputs("<i>",r);
        ap_rputs(VERSION,r);
        ap_rputs("</i>",r);

        ap_rputs("</body></html>",r);

        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r, "[mod_fence] Mitigation Triggered, dropping request.");

        ap_finalize_request_protocol(r);
        r->output_filters = r->proto_output_filters;
        apr_hook_deregister_all(); //DONT PASS THIS REQUEST TOWARDS

        return OK;
    }
    /** MITIGATE **/


    return DECLINED;
}
/** FENCE_POST_READ_REQUEST **/

static const command_rec fence_cmds[] = {
    AP_INIT_FLAG(
                 "Fence_Enable",
                 fence_enable,
                 NULL,
                 RSRC_CONF,
                 "Enable mod_fence"
                 ),
    AP_INIT_TAKE1(
                 "Fence_ChildTimeout",
                 fence_settimeout,
                 NULL,
                 RSRC_CONF,
                 "Declare the Child Timeout"
                 ),
    AP_INIT_TAKE1(
                 "Fence_MitigateSoftRequests",
                 fence_setSoftReqs,
                 NULL,
                 RSRC_CONF,
                 ""
                 ),
    AP_INIT_TAKE1(
                 "Fence_MitigateHardRequests",
                 fence_setHardReqs,
                 NULL,
                 RSRC_CONF,
                 ""
                 ),
    { NULL }
};


static void fence_register_hooks(apr_pool_t *p) 
{
    ap_hook_post_config(init_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(fence_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA fence_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    fence_create_server_cfg,
    NULL,
    fence_cmds,
    fence_register_hooks,
};
