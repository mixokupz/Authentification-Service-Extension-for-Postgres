#include "postgres.h"
#include "fmgr.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/shmem.h"
#include "miscadmin.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/elog.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lib/stringinfo.h"
PG_MODULE_MAGIC;
#define SERVER_PORT 9998

void _PG_init(void);
PGDLLEXPORT void exe_serv_main(Datum);

void exe_serv_main(Datum main_arg){
    //nado eche rasparsit' database 
    BackgroundWorkerUnblockSignals();
    BackgroundWorkerInitializeConnection("item", NULL, 0);

    //nado podderzhat IPv4 socket
    int server_sock;
    int client_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int result;
    char buffer[1024];
    char send[30];
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(server_sock,SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bind(server_sock,(struct sockaddr *)&server_addr,sizeof(server_addr));
    listen(server_sock, 5);


    while(1){
	int clen = sizeof(client_addr);
    	client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &clen);
	int n_read = read(client_sock, buffer, sizeof(buffer));
	buffer[n_read] = '\0';
	
	AcceptInvalidationMessages();
        CommandCounterIncrement();

    	StartTransactionCommand();
    	PushActiveSnapshot(GetTransactionSnapshot());
	
    	if(SPI_connect() != SPI_OK_CONNECT){
    		ereport(ERROR, (errmsg("SPI_connect error")));
	}
	int ret = SPI_execute(buffer, true, 0);
	if(ret != SPI_OK_SELECT){
    	    ereport(ERROR,(errmsg("SPI_excute error")));
	}
	
     char res_buf[9000];
     int offset = 0; 
     if (SPI_processed > 0 && SPI_tuptable != NULL) {
    	SPITupleTable *tuptable = SPI_tuptable;
   	TupleDesc tupdesc = tuptable->tupdesc;
    	uint64 rows = SPI_processed;
    	int cols = tupdesc->natts;

    	for (int j = 0; j < cols; j++) {
            const char *colname = NameStr(tupdesc->attrs[j].attname);
	    offset += snprintf(res_buf + offset, sizeof(res_buf) - offset, "%s%s", colname, (j < cols - 1) ? "\t" : "\n");
    	}

    	for (uint64 i = 0; i < rows; i++) {
            HeapTuple tuple = tuptable->vals[i];
            for (int j = 0; j < cols; j++) {
                char *val = SPI_getvalue(tuple, tupdesc, j + 1);
                offset += snprintf(res_buf + offset, sizeof(res_buf) - offset,"%s%s", val ? val : "NULL", (j < cols - 1) ? "\t" : "\n");
            }
        }
    }
     	res_buf[offset] = '\0';
	write(client_sock, res_buf, strlen(res_buf));
	SPI_finish();
	PopActiveSnapshot();
	CommitTransactionCommand();
	close(client_sock);
        	
    }
}

void _PG_init(void){
    BackgroundWorker worker;
    memset(&worker, 0,sizeof(worker));
    worker.bgw_flags = BGWORKER_BACKEND_DATABASE_CONNECTION | BGWORKER_SHMEM_ACCESS;
    worker.bgw_start_time = BgWorkerStart_ConsistentState;
    worker.bgw_restart_time = BGW_NEVER_RESTART;
    snprintf(worker.bgw_name,BGW_MAXLEN,"exe_serv_worker");
    snprintf(worker.bgw_library_name,BGW_MAXLEN,"exe_worker");
    snprintf(worker.bgw_function_name,BGW_MAXLEN,"exe_serv_main");
    worker.bgw_main_arg = (Datum)0;
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);

}
