#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <string.h>
#include <stdarg.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "common.h"

static config_t config;

static void *shm;

static void log_msg_file(const char *filename, const char *format, ...){
	FILE *file = fopen(filename, "a");
	if (file != NULL) {
		time_t t = time(NULL);
		struct tm *tm1 = localtime(&t);
		
		char buffer[256];
		va_list args;
		va_start (args, format);
		vsprintf (buffer, format, args);
		va_end (args);
		
		fprintf(file, "%d-%d-%d %d:%d:%d %s\n", 	tm1->tm_mday, 
													tm1->tm_mon, 
													(tm1->tm_year-100), 
													
													tm1->tm_hour, 
													tm1->tm_min, 
													tm1->tm_sec, 
													
													buffer );
		fclose(file);
	}
}

static void log_msg(const char *format, ...){
	char filename[1024];
	snprintf(filename, sizeof(filename), "%s/redalert.log", config.logDirectory);
	
	char buffer[256];
	va_list args;
	va_start (args, format);
	vsprintf (buffer,format, args);
	va_end (args);
	
	log_msg_file(filename, buffer);
}

static void addData(shm_data_t *data, const char *ip, int ri){
	
	int item_already_exist = 0;
	for(int i=0; i<data->size; i++){
		if ( 	data->counters[i].rule_ix==ri && 
				strcmp(data->counters[i].ip, ip)==0 ){
					
			data->counters[i].count++;
			item_already_exist = 1;
			break;
		}
	}
	
	if ( item_already_exist==0 ){
		if ( data->size < IP_COUNT_MAX ){
			
			strcpy(	data->counters[data->size].ip, ip );
			data->counters[data->size].count = 1;
			data->counters[data->size].first_time = time(NULL);
			data->counters[data->size].rule_ix = ri;
			
			data->size++;
		}
	}
}

static int str_ends_with(const char * str, const char * suffix) {

	if( str == NULL || suffix == NULL )
		return F;

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if(suffix_len > str_len)
		return F;

	if ( strncmp( str + str_len - suffix_len, suffix, suffix_len )==0 ){
		return T;
	}else{
		return F;
	}
}

static void resetData(shm_data_t *data){
	data->version_no = VERSION_NO;
	data->size = 0;
}

static shm_data_t *beginData(){
	int shm_size = sizeof(shm_data_t);
	int shm_perm = 0666;// octal number	
	
	int shmid;
	int newCreated = 0;
	
	if ((shmid = shmget(config.shmKeyNumber, shm_size, shm_perm)) < 0) {
		if ((shmid = shmget(config.shmKeyNumber, shm_size, IPC_CREAT | IPC_EXCL | shm_perm)) < 0) {
			log_msg("Shared memory failed. Please change 'Shm_Key_Number' value!");
			return NULL;
		}else{
			log_msg("shmget IPC_CREAT");
			newCreated = 1;
		}
	}
	
	if ((shm = shmat(shmid, NULL, 0)) == (void *) -1) {
		log_msg("shmat return -1");
		return NULL;
	}
	
	shm_data_t *data = (shm_data_t *)shm;
	
	if ( newCreated==1 ){
		resetData(data);
		log_msg("data initialized");
		return NULL;
	}else if ( data->version_no!=VERSION_NO ){
		log_msg("data version is wrong!");
		shmdt(shm);
		shmctl(shmid, IPC_RMID, NULL);
		log_msg("data deleted!");
		return NULL;
	}
	
	return data;
}

static void endData(){
	shmdt(shm);
}

static int isRuleExist(	const char *r_host_name, 
						const char *r_uri_end, 
						const char *host_name, 
						const char *uri){

	if ( 	strcmp(	r_host_name, "*" )==0 || 
			strcmp(	r_host_name, host_name )==0 ){
				
		return str_ends_with( uri, r_uri_end );
	}
	
	return F;
}

static int redalert_handler(request_rec *r)
{
	for(int i=0; i<config.safe_ips_count; i++){
		if ( strcmp(r->useragent_ip, config.safe_ips[i].ip)==0 ){
			return DECLINED;
		}
	}
	
	for(int i=0; i<config.watchs_count; i++){
		if ( isRuleExist(	config.watchs[i].host_name, 
							config.watchs[i].uri_end, 
							r->server->server_hostname, 
							r->uri ) ){
			
			log_msg_file(config.watchs[i].filepath, "%s %s %s",		r->useragent_ip, 
																	r->server->server_hostname, 
																	r->uri );
		}
	}
	
	int rule_exist = 0;
	for(int ri=0; ri<config.ruleCount; ri++){
		if ( isRuleExist(	config.rules[ri].host_name, 
							config.rules[ri].uri_end, 
							r->server->server_hostname, 
							r->uri ) ){
			rule_exist = 1;
			break;
		}
	}
	if ( rule_exist==0 ){
		return DECLINED;
	}
	
	shm_data_t *data = beginData();
	if ( data==NULL ){
		return DECLINED;
	}
	
	for(int ri=0; ri<config.ruleCount; ri++){
		if ( isRuleExist(	config.rules[ri].host_name, 
							config.rules[ri].uri_end, 
							r->server->server_hostname, 
							r->uri ) ){
			addData(data, r->useragent_ip, ri);
		}
	}
	
	time_t time_now = time(NULL);
	for(int ci=0; ci<data->size; ci++){
		rule_t 			*rule = &config.rules[data->counters[ci].rule_ix];
		ip_counter_t 	*counter = &data->counters[ci];
		
		// rps : request per second
		if ( time_now >= (counter->first_time+rule->second) ){
			
			float rule_rps 		= (float)rule->count / rule->second;
			int time_diff 		= time_now - counter->first_time;
			float counter_rps 	= (float)counter->count / time_diff;
			
			if ( counter_rps >= rule_rps ){
				log_msg(	"%d requests in %d seconds from %s [AddRule %s %s %d %d %s]", 
							counter->count,
							time_diff,
							r->useragent_ip,
							rule->host_name,
							rule->uri_end,
							rule->second,
							rule->count,
							rule->ipset_name );
				
				char cmd[512];
				sprintf(cmd, "sudo ipset -A %s %s", rule->ipset_name, 
													counter->ip );

				int ret = system(cmd);
			}
			
			counter->garbage = 1;
		}else{
			counter->garbage = 0;
		}
	}
	
	int iRead = 0;
	int iWrite = 0;
	while( iRead < data->size ){
		
		if ( data->counters[iRead].garbage==0 ){
			if ( iWrite<iRead ){
				data->counters[iWrite] = data->counters[iRead];
			}
			iWrite++;
		}
		
		iRead++;
	}
	data->size = iWrite;
	
	endData();
	
    return DECLINED;
}

static const char *cfg_logDirectory(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.logDirectory = arg;
    return NULL;
}

static const char *cfg_AddRule(cmd_parms *cmd, void *cfg, int argc, char *const argv[])
{
	if ( argc==5 && config.ruleCount<RULE_MAX ){
		
		strcpy(config.rules[config.ruleCount].host_name, 	argv[0]);
		strcpy(config.rules[config.ruleCount].uri_end, 		argv[1]);
		config.rules[config.ruleCount].second 	= atoi(argv[2]);
		config.rules[config.ruleCount].count 	= atoi(argv[3]);
		strcpy(config.rules[config.ruleCount].ipset_name, 	argv[4]);
		
		config.ruleCount++;
	}
	
    return NULL;
}

static const char *cfg_safeIp(cmd_parms *cmd, void *cfg, int argc, char *const argv[])
{
	config.safe_ips_count = 0;
	for(int i=0; i<SAFE_IP_MAX && i<argc; i++){
		strcpy(config.safe_ips[i].ip, argv[i]);
		config.safe_ips_count++;
	}
	
    return NULL;
}

static const char *cfg_watch(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2, const char *arg3)
{	
	if ( config.watchs_count<WATCH_MAX ){
		strcpy(config.watchs[config.watchs_count].host_name, arg1);
		strcpy(config.watchs[config.watchs_count].uri_end, arg2);
		strcpy(config.watchs[config.watchs_count].filepath, arg3);
		
		config.watchs_count++;
	}
	
    return NULL;
}

static const command_rec        configList[] =
{
	AP_INIT_TAKE1(		"LogDirectory", 		
						cfg_logDirectory, 		
						NULL, 
						RSRC_CONF, 
						"LogDirectory [/home/test]"),
						
	AP_INIT_TAKE_ARGV(	"AddRule",
						cfg_AddRule, 		
						NULL, 
						RSRC_CONF, 
						"AddRule [*|host-name] [uri-end] [second] [request-count] [ipset-name]"),
						
	AP_INIT_TAKE_ARGV(	"SafeIp",
						cfg_safeIp,
						NULL,
						RSRC_CONF,
						"Safe [IP1] [IP2] ..." ),
						
	AP_INIT_TAKE3(		"Watch",
						cfg_watch, 		
						NULL, 
						RSRC_CONF, 
						"Watch [*|host-name] [uri-end] [filepath]"),
	
    { NULL }
};

// neden 3 kere çağrılıyor?
static void register_hooks(apr_pool_t *pool)
{
	config.logDirectory			= "/home";
	config.shmKeyNumber			= SHM_KEY_NUMBER;
	config.ruleCount 			= 0;
	config.safe_ips_count 		= 0;
	config.watchs_count			= 0;
		
	shm_data_t *data = beginData();
	if ( data!=NULL ){
		resetData(data);
		endData();
	}
	
	// ap_hook_handler does not work when ddos happening
	ap_hook_quick_handler(redalert_handler, NULL, NULL, APR_HOOK_FIRST);
}

//
module AP_MODULE_DECLARE_DATA   redalert_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    configList,
    register_hooks
};
