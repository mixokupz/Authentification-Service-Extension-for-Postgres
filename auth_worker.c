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

PG_MODULE_MAGIC;

#define SOCKET_PATH "/tmp/auth_serv.sock"
#define SERVER_PORT 9999
static int server_fd = -1;

void _PG_init(void);
PGDLLEXPORT void auth_serv_main(Datum);

void auth_serv_main(Datum main_arg){
    BackgroundWorkerUnblockSignals();
    BackgroundWorkerInitializeConnection("postgres", NULL, 0);

    //nado podderzhat IPv4 socket
    int server_sock;
    int client_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int result;
    char buffer[512];
    char* username;
    char* password;
    char send;
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
	read(client_sock, buffer, sizeof(buffer) - 1);

        AcceptInvalidationMessages();
        CommandCounterIncrement();

    	StartTransactionCommand();
    	PushActiveSnapshot(GetTransactionSnapshot());
	
    	if(SPI_connect() != SPI_OK_CONNECT){
    		ereport(ERROR, (errmsg("SPI_connect error")));
	}

	//pasring
	username = strtok(buffer, ":");
	password = strtok(NULL, ":");
	//snprintf(buffer,sizeof(buffer),"%s %s",username,password);

	const char* query = "SELECT 1 FROM pg_authid WHERE rolname = $1 AND rolpassword = $2";
	Oid argtypes[2] = {TEXTOID, TEXTOID};
	Datum values[2];
	char nulls[2] = {' ', ' '};
	values[0] = CStringGetTextDatum(username);
	values[1] = CStringGetTextDatum(password);
    	int ret = SPI_execute_with_args(query,2,argtypes,values,nulls,true,2);
	if(ret != SPI_OK_SELECT){
    	    ereport(ERROR,(errmsg("SPI_excute_with_args error")));
	}
	if(SPI_processed > 0){
	    send = 1;
	}else{
	    send = 0;
	}
	//printf("Recieved: %s",buffer);
	write(client_sock,&send,sizeof(send));
	close(client_sock);
    
    SPI_finish();
    
    PopActiveSnapshot();
    CommitTransactionCommand();
    }
}

void _PG_init(void){
    BackgroundWorker worker;
    memset(&worker, 0,sizeof(worker));
    worker.bgw_flags = BGWORKER_BACKEND_DATABASE_CONNECTION | BGWORKER_SHMEM_ACCESS;
    worker.bgw_start_time = BgWorkerStart_ConsistentState;
    worker.bgw_restart_time = BGW_NEVER_RESTART;
    snprintf(worker.bgw_name,BGW_MAXLEN,"auth_serv_worker");
    snprintf(worker.bgw_library_name,BGW_MAXLEN,"auth_worker");
    snprintf(worker.bgw_function_name,BGW_MAXLEN,"auth_serv_main");
    worker.bgw_main_arg = (Datum)0;
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);

}
