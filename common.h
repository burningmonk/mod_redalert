#define RULE_MAX 		20
#define IP_COUNT_MAX 	5000
#define SAFE_IP_MAX 	100
#define WATCH_MAX		100
#define VERSION_NO 		10009
#define SHM_KEY_NUMBER 	444555

#define T	1
#define F	0

typedef struct {
	char 	ip[16];
}ip_t;

typedef struct {
	char 	host_name[256];
	char 	uri_end[256];
	int 	second;
	int 	count;
	char 	ipset_name[256];
	
}rule_t;

typedef struct ip_counter{
	char 	ip[16];
	int 	count;
	time_t	first_time;	
	int 	rule_ix;
	
	int 	garbage;
} ip_counter_t;

typedef struct shm_data{
	unsigned long	version_no;
	
	ip_counter_t 	counters[IP_COUNT_MAX];
	int 			size;
}shm_data_t;

typedef struct {
	char 	host_name[256];
	char 	uri_end[256];
	char 	filepath[256];
}watch_t;

typedef struct {
	const char *logDirectory;
	int         shmKeyNumber;
	rule_t		rules[RULE_MAX];
	int			ruleCount;
	
	ip_t 		safe_ips[SAFE_IP_MAX];
	int 		safe_ips_count;
	
	watch_t		watchs[WATCH_MAX];
	int			watchs_count;
}config_t;
