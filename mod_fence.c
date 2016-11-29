/*
   Copyright 2016 Hlavaji Viktor / DaVieS
        nPulse.net / davies@npulse.net

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

#define VERSION "mod_fence/0.2a"

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
    int                maxreqs;
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
    cfg->maxreqs = 0;

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

/** FENCE_SETMAXREQS **/
static const char *fence_setmaxreqs(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fence_server_cfg *cfg = (fence_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &fence_module);

    cfg->maxreqs = atoi(arg);
    return NULL;

}
/** FENCE_SETMAXREQS **/


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
    int online_procs = 0;

    pid_t *pid_buffer, worker_pid;
    char *stat_buffer;

    int *thread_idle_buffer = NULL;
    int *thread_busy_buffer = NULL;
    clock_t tu, ts, tcu, tcs;
    ap_generation_t mpm_generation, worker_generation;

    apr_time_t nowtime = apr_time_now();
    tu = ts = tcu = tcs = 0;


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


                if(cfg->maxreqs && !strcmp(ws_record->client, r->DEF_IP) && ( ws_record->status == SERVER_BUSY_READ || ws_record->status == SERVER_BUSY_WRITE || ws_record->status == SERVER_GRACEFUL))
                {
                    online_procs++;
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
                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r, "Killing Stucked Child: %d", ps_record->pid);
                        kill(ps_record->pid, SIGKILL);
                    }
                }

            } 
        }

        if(online_procs > cfg->maxreqs)
        {
          /*
          ap_set_content_type(r, "text/html");
          char error_page[] = "<html><head>" \
          "<meta name='robots' content='NOINDEX, NOFOLLOW'>" \
          "</meta><title>mod_fence / Request Terminated</title>" \
          "</head>" \
          "<body style='margin: 20px; padding: 20px; color: #333;'>" \
          "<h1>Your request terminated due to <b>Denial Of Service</b> Prevention.</h1>" \
          "<br /><br />" \
          "You are requested more than %i parallel requests that is seems non-usual activity.<br /><br />" \
          "In any other case please contact with the server or website owner / administartor.<br /><br />%s" \
          "</body></html>";

          char temp[4096];
          temp[0] = 0x00;

          sprintf(temp,error_page,cfg->maxreqs,r->server->server_admin);
          ap_rputs(temp, r);
          */

          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r, "Denial Of Service Mitigation Triggered: %d", online_procs);

          return 503;

        }


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
                 "Fence_MaxRequests",
                 fence_setmaxreqs,
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
