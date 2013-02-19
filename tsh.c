/* 
 * tsh - A tiny shell program with job control
 *
 * You __MUST__ add your user information here below
 *  
 * === User information ===
 * Group: JeeBoy
 * User 1: ingvars11
 * SSN: 2107862529
 * User 2: elisae11
 * SSN: 2807815099
 * === End User Information ===
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv); 
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

/* My helper routines */
pid_t Fork(void);
void Execve(char **argv, char **env);
void Sigemptyset(sigset_t *set);
void Sigprocmask(int change, const sigset_t *set, sigset_t *oset);
void Sigaddset(sigset_t *set, int signo);
void set_job_to_fg(char **argv);
void set_job_to_bg(char **argv);
int change_job_state(pid_t pid, int old_state, int new_state);
pid_t get_my_pid(char **argv);
/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
            switch (c) {
            case 'h':             /* print help message */
                usage();
            break;
            case 'v':             /* emit additional diagnostic info */
                verbose = 1;
            break;
            case 'p':             /* don't print a prompt */
                emit_prompt = 0;  /* handy for automatic testing */
            break;
            default:
                usage();
        }
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler); 

    /* Initialize the job list */
    initjobs(jobs);

    /* Execute the shell's read/eval loop */
    while (1) {

        /* Read command line */
        if (emit_prompt) {
            printf("%s", prompt);
            fflush(stdout);
        }
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");
        if (feof(stdin)) { /* End of file (ctrl-d) */
            fflush(stdout);
            exit(0);
        }

        /* Evaluate the command line */
        eval(cmdline);
        fflush(stdout);
        fflush(stdout);
    } 

    exit(0); /* control never reaches here */
}
  
/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline) 
{   /* Passa að slökkva á signalhandlers á meðan eval er að vinna með skipunina */
    char *my_argv[MAXARGS];
    char buf[MAXLINE];
    int back_ground;
    pid_t pid;
    sigset_t mask;

    strcpy(buf, cmdline);
    back_ground = parseline(buf, my_argv);
    
    if (my_argv[0] == NULL)
        return;
 
    if (!builtin_cmd(my_argv)){
        // Blocking signals when i call fork and execve
        Sigemptyset(&mask);
        Sigaddset(&mask, SIGCHLD); /* Block SIGCHLG */
        Sigaddset(&mask, SIGINT);
        Sigaddset(&mask, SIGTSTP);
        Sigprocmask(SIG_BLOCK, &mask, NULL); 

        if ((pid = Fork()) == 0 && (setpgid(0, 0) != -1)) { 
            
            Sigprocmask(SIG_UNBLOCK, &mask, NULL); /*Unblock SIGCHLD */
            Execve(my_argv, environ);
        } else if(pid > 0){

            if (!back_ground) {  
                addjob(jobs, pid, FG, cmdline);
                Sigprocmask(SIG_UNBLOCK, &mask, NULL);
                waitfg(pid);
            } else {
                    // I need to put the job in background
                addjob(jobs, pid, BG, cmdline);
                Sigprocmask(SIG_UNBLOCK, &mask, NULL);
                printf("[%d] (%d) %s.\n", pid2jid(pid), pid, cmdline);
            } 
            
        }    
   } 
   
   return;
}

/*
 * Wrapper function around sigprocmask
 */
void Sigprocmask(int change, const sigset_t *set, sigset_t *oset)
{
    if (sigprocmask(change, set, oset) < 0) {
        printf("Error in sigprocmask function.\n");
        exit(0);
    }
}

/*
 * Wrapper function for sigemptyset
 */
void Sigemptyset(sigset_t *set)
{
    sigemptyset(set);
}

/*
 * Wrapper function for sigaddset
 */
void Sigaddset(sigset_t *set, int signo)
{
    if(sigaddset(set, signo) < 0){
        printf("Error occured in sigaddset function.\n");
        exit(0);
    }
}

/*
 * Wrapper around execve function
 */
void Execve(char **argv, char **env) 
{
    if(execve(argv[0], argv, env) < 0) {
        printf("%s : Command not found.\n", argv[0]);
        exit(0);
    }
}

/*
 * The wrapper as described in the book
 * Computer System
 */
pid_t Fork(void)
{
    pid_t pid;

    if((pid = fork()) < 0)
        unix_error("Fork error");

    return pid;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv) 
{
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
	    buf++;

    /* Build the argv list */
    argc = 0;
    if (*buf == '\'') {
	    buf++;
	    delim = strchr(buf, '\'');
    }
    else {
	    delim = strchr(buf, ' ');
    }

    while (delim) {
	    argv[argc++] = buf;
	    *delim = '\0';
	    buf = delim + 1;
	    while (*buf && (*buf == ' ')) /* ignore spaces */
	        buf++;

	    if (*buf == '\'') {
	        buf++;
	        delim = strchr(buf, '\'');
	    }
	    else {
	        delim = strchr(buf, ' ');
	    }
    }
    argv[argc] = NULL;
    
    if (argc == 0)  /* ignore blank line */
	    return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc-1] == '&')) != 0) {
	    argv[--argc] = NULL;
    }
    return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_cmd(char **argv) 
{   
    if (!strcmp(argv[0], "quit")) /* quit command */
        exit(0);
   
    if (!strcmp(argv[0], "jobs")){
        listjobs(jobs);
        return 1;    
    }

    if (!strcmp(argv[0], "bg") || !strcmp(argv[0], "fg")){
        do_bgfg(argv);
        return 1;
    }

    if (!strcmp(argv[0], "&")) /* not a singelton */
        return 1;

    return 0;     /* not a builtin command */
}

/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv) 
{
    if (!strcmp(argv[0], "fg")){
        set_job_to_fg(argv);
        return;
    }
    
    if (!strcmp(argv[0], "bg")){
        set_job_to_bg(argv);
        return;
    }
}

/*
 * Setting a job into the fg process
 */
void set_job_to_fg(char **argv)
{
    pid_t pid;
    if (argv[1] == NULL){ 
        printf("Command requries PID or %%jobid\n");
        return;
    }


    if((pid = get_my_pid(argv)) == 0){
        printf("%d is not valid pid.\n", pid);
        return;
    }

    if ((change_job_state(pid, ST | BG, FG)) < 1)
        unix_error("Fg did not work\n");


    if (verbose){
        printf("Setting process %d into foreground.\n", pid);
    }


    return; 
}

/*
 * Setting a job into the bg process
 */
void set_job_to_bg(char **argv)
{
    pid_t pid;
    if (argv[1] == NULL){
        printf("Command requries PID or %%jobid\n");
        return;
    } else if ((pid = get_my_pid(argv)) == 0){
        printf("%d is not valid pid.\n", pid);
        return;
    }

    if ((change_job_state(pid, ST | BG, FG)) < 1)
        unix_error("Bg did not work\n");

     if (verbose){
        printf("Setting process %d into background.\n", pid);
    }
    return;
}

/*
 * Get my pid is a custom funciton to 
 * help with the fg and bg functions, you are supposed 
 * to be able to put a process either by giving it the pid or jid
 */
pid_t get_my_pid(char **argv)
{   
    int job_id = 0;
    pid_t pid = 0;
    int i;
    char *found;
    struct job_t* job;
    if (verbose){
        printf("In BG.\n");
    }
    
    for(i = 1; argv[i] != NULL; i++){
        if((found = strchr(argv[i], '%')) != NULL) {
            job_id = atoi(++found); 
            break;
        } else {
            pid = atoi(argv[i]);
            break;
        }
    }
    
    if (pid == 0){
        if ((job = getjobjid(jobs, job_id)) == NULL){
            return 0;
        }
        pid = job->pid;
        return pid;
    } else {
        if ((job = getjobpid(jobs, pid)) == NULL){
            return 0;
        }
        pid = job->pid;
        return pid;
    }

    return 0;
   
}   


/*
 * Change job state, if you want to put a specific job into background,
 * foreground or have it stopped
 */
int change_job_state(pid_t pid, int old_state, int new_state)
{
    struct job_t *job;

    if (verbose)
        printf("Changing job pid %d state %d to %d.\n",pid, old_state, new_state);

    if(pid < 1)
        return 0;

    job = getjobpid(jobs, pid);
    if(new_state == FG){
        job->state = new_state;
        kill(-(job->pid), SIGCONT);
        waitfg(job->pid);
    } 
    else if(new_state == BG){
        job->state = new_state;
        kill(-(job->pid), SIGCONT);
        printf("[%d] (%d) %s\n", job->jid, job->pid, job->cmdline);
    } else
        return 0; 
   
    return 1;
}


/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid)
{   // Just a busy loop until pid == 0
    while (pid == fgpid(jobs))
        sleep(0);
}



/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig) 
{
    pid_t pid;
    pid_t fg_job = fgpid(jobs);
    int status;
    
    if (verbose) {
        printf("In sigchld %d.\n", fgpid(jobs));
        printf("Job [%d] %d terminted by signal %d.\n", pid2jid(fg_job), fg_job, sig);
    }

    
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0){
      
        if (verbose){
            printf("Status on sigchld : %d\n", status);
            printf("Wifstopped : %d\n", WIFSTOPPED(status));
        }

        if (WIFSTOPPED (status)){
             getjobpid(jobs, pid)->state = ST;
             printf("Job [%d] (%d) stopped by signal %d.\n", pid2jid(pid), pid, WSTOPSIG(status));
        } else if (WIFSIGNALED(status)){
            printf("Job [%d] (%d) terminted by signal %d.\n", pid2jid(pid), pid, WTERMSIG(status));
            if ((deletejob(jobs, pid)) < 1)
                unix_error("Deleting a process in sigchld failed");
        } else {
             if ((deletejob(jobs, pid)) < 1)
                unix_error("Deleting a process in sigchld failed");
        }
           
    }
    
    return;    
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig) 
{ 
    pid_t pid = fgpid(jobs);
    if (verbose)
        printf("In handler for sigint %d \n", pid);
    
    if (pid != 0)
        kill(-pid, SIGINT);

    return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig) 
{
    pid_t pid = fgpid(jobs);
    if (verbose)
        printf("In handler for sigstp %d \n", pid);

    if (pid != 0)
        kill(-pid, SIGTSTP);
    return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	    clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	    if (jobs[i].jid > max)
	        max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
    int i;
    
    if (pid < 1)
	    return 0;

    for (i = 0; i < MAXJOBS; i++) {
	    if (jobs[i].pid == 0) {
	        jobs[i].pid = pid;
	        jobs[i].state = state;
	        jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
                nextjid = 1;
            
            strcpy(jobs[i].cmdline, cmdline);
            
            if(verbose){
                printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
	    }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
    int i;

    if (pid < 1)
	    return 0;

    for (i = 0; i < MAXJOBS; i++) {
	    if (jobs[i].pid == pid) {
	        clearjob(&jobs[i]);
	        nextjid = maxjid(jobs)+1;
	        return 1;
	    }
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	    if (jobs[i].state == FG)
	        return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
	    return NULL;
    for (i = 0; i < MAXJOBS; i++)
	    if (jobs[i].pid == pid)
	        return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
    int i;

    if (jid < 1)
	    return NULL;
    for (i = 0; i < MAXJOBS; i++)
	    if (jobs[i].jid == jid)
	        return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
    int i;

    if (pid < 1)
	    return 0;
    for (i = 0; i < MAXJOBS; i++)
	    if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
    int i;
    
    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid != 0) {
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state) {
            case BG: 
                printf("Running ");
                break;
            case FG: 
                printf("Foreground ");
                break;
            case ST: 
                printf("Stopped ");
                break;
            default:
                printf("listjobs: Internal error: job[%d].state=%d ", 
                   i, jobs[i].state);
            }
            printf("%s", jobs[i].cmdline);
        }
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) 
{
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
	    unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) 
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}
