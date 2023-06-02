#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <signal.h>



struct linux_dirent {
    unsigned long  d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};


//globalne spremenljivke
#define MAX_TOKENS 25
#define ST_VGR_UKAZ 31 //30 ukazov + ena funkcija za naredit nic
int nacin; // 0: skriptni ; 1: interaktivni
char ime_lupine[9] = "mysh";
char line[1000] = {0};
char izhodni_izpis[2000] = {0};
char* tokens[MAX_TOKENS];
int token_count;
int st_simbolov; //stevilo tokenov
int izhodni_status;
char procfs_path[1000] = "/proc";

int preusmeritev_izhoda; int preusmeritev_vhoda;
char preusmerjen_izhod[256] = {0}; char preusmerjen_vhod[256] = {0};
int stdin_kopija; int stdout_kopija;

int tabela_cevi[20][2]; //ce naj bo tokenov vsaj 20, potem rabi bit cevi vsaj 19 - en token pozre "pipes"
int naslednja_stopnja_cevovoda;
int stevilo_stopenj;


int ni_ukaz(); int help(); int status(); int moj_exit(); int name(); int print(); int echo(); int pid(); int ppid(); int dirchange(); int dirwhere(); int dirbase(); int dirmake(); 
int dirremove(); int dirlist(); int linkhard(); int linksoft(); int linkread(); int linklist(); int moj_unlink(); int moj_rename(); int moj_remove(); int cpcat(); int sysinfo(); 
int shellinfo(); int proc(); int pids(); int pinfo(); int waitone(); int waitall(); int pipes(); int zunanji_ukaz();
const char* tabela_imen_ukazov[] = {
    "", "help", "status", "exit", "name", "print", "echo", "pid", "ppid", "dirchange", "dirwhere", "dirbase", "dirmake", "dirremove", "dirlist", "linkhard", "linksoft",
    "linkread", "linklist", "unlink", "rename", "remove", "cpcat", "sysinfo", "shellinfo", "proc", "pids", "pinfo", "waitone", "waitall", "pipes"
};
const int (*tabela_kazalcev_funkcij_ukazov[])() = {
    ni_ukaz, help, status, moj_exit, name, print, echo, pid, ppid, dirchange, dirwhere, dirbase, dirmake, dirremove, dirlist, linkhard, linksoft,
    linkread, linklist, moj_unlink, moj_rename, moj_remove, cpcat, sysinfo, shellinfo, proc, pids, pinfo, waitone, waitall, pipes, zunanji_ukaz
};


int ukaz_lookup(){
    /* redundantno
    //prvi token je prazen - vpisan je bil presledek
    int zacetek_ukaza_tokeni;
    while(tokens[zacetek_ukaza_tokeni]==NULL && zacetek_ukaza_tokeni<MAX_TOKENS){
        zacetek_ukaza_tokeni++;
    }
    if(zacetek_ukaza_tokeni==MAX_TOKENS){
        //ni bilo ukaza -- prazna vrstica/komentar/...
        return 0;
    } */

    if(tokens[0] == NULL) return 0; //ce ni ukaza -- prazna vrstica, presledki, zakomentirano (samo narekovaji se vedno povzrovi napako ampak to ni vrstica v pravilni obliki)
    //v tabeli imen ukazov poisce (prvi token) in vrne njegov indeks
    int found = 0;
    int indeks = -1;
    for(indeks = 0; indeks<ST_VGR_UKAZ && !found; indeks++){
        if(strcmp(tabela_imen_ukazov[indeks], tokens[0]) == 0){
            found = 1;
            break;
        }
    }

    
    if(strncmp(tokens[token_count-1],">",1) == 0){
        preusmeritev_izhoda = 1;
        strcpy(preusmerjen_izhod, tokens[token_count-1] + 1);
        tokens[--token_count] = NULL;
    }
    if(strncmp(tokens[token_count-1],"<",1) == 0){
        preusmeritev_vhoda = 1;
        strcpy(preusmerjen_vhod, tokens[token_count-1] + 1);
        tokens[--token_count] = NULL;
    }

    return indeks;
}

int tokenize (char* vrstica, char** tokens){
    //razbije na tokene (simbole)
    
    int running_indeks = 0;
    int token_indeks = 0;
    int dolzina_vrstice = strlen(vrstica);
    int v_narekovaju = 0;
    int zacni_nov_token = 1;

    //prvi token se zacne na zacetku vrstice (ce so vse vrstice v pravilni obliki naj se ne bi zacel z presledkom ali ")
    //*(tokens+token_indeks++) = vrstica;

    //sprehod cez vrstico
    while(running_indeks < dolzina_vrstice){

        if(!v_narekovaju){
            //ni v narekovajih
            if(*(vrstica+running_indeks) == ' '){
                *(vrstica+running_indeks) = '\0'; //koncamo prejsni token
                zacni_nov_token = 1;
            }
            else if(*(vrstica+running_indeks) == '"'){
                *(tokens+token_indeks++) = vrstica + ++running_indeks; //narekovaj preskocimo in zacnemo nov token (ta narekovaj ostane)
                v_narekovaju = 1;
            }
            else if(*(vrstica+running_indeks) == '\n'){
                *(vrstica+running_indeks) = '\0'; // \n nocemo v tokenu - do tega pride predvidoma samo na koncu vrstice (vhoda)
            }
            else if(*(vrstica+running_indeks) == '#'){
                *(vrstica+running_indeks) = '\0'; //nastavimo konec
                break;
            }
            else{
                if(zacni_nov_token){
                    *(tokens+token_indeks++) = vrstica + running_indeks;
                    zacni_nov_token = 0;
                } 
            }

        }
        else{
            //je v narekovaju
            if(*(vrstica+running_indeks) == '"'){
                v_narekovaju = 0;
                *(vrstica+running_indeks) = '\0'; //narekovaja nocemo kot del simbola/tokena, zato ga unicimo
                //za narekovajem (razen v primeru, da je to zadnji simbol v vrstici), zdaj pride se presledek, ki bo prav tako unicen v \0 
                //in za njim se bo zacel naslednji token
            }
        }

        running_indeks++;

    }//while cez vrstico

    st_simbolov = token_indeks;
    *(tokens+token_indeks) = NULL; //da za zihr vemo kdaj je konec ker samo povozimo od prejsnje iteracije in je od prej notr

    return st_simbolov; 
}

//izvajanje zunanjega ukaza
int zunanji_ukaz(){
    int pid = fork();
    int status_za_return;
    
    if(pid < 0){
        //fork fail
        status_za_return = errno;
        perror("zunanji ukaz");
        return status_za_return;
    }
    else if(pid == 0){
        if(preusmeritev_izhoda){
            int p_i_fd = open(preusmerjen_izhod, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if(p_i_fd < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            if(dup2(p_i_fd, 1) < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            if(close(p_i_fd) < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            preusmeritev_izhoda = 0;
        }
        if(preusmeritev_vhoda){
            int p_v_fd = open(preusmerjen_vhod, O_RDONLY);
            if(p_v_fd < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            if(dup2(p_v_fd, 0) < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            if(close(p_v_fd) < 0){
                izhodni_status = errno;
                perror("preusmeritev izhoda");
                exit(izhodni_status);
            }
            preusmeritev_vhoda = 0;
        }

        execvp(tokens[0], tokens);
        perror("zunanji ukaz");
        exit(EXIT_FAILURE);
    }//otrok
    else{
        //koda starsa
        if(waitpid(pid, &status_za_return, 0) < 0){
            //wait fail
            status_za_return = errno;
            perror("zunanji ukaz");
            return status_za_return;
        }
    }//stars

    if(WIFEXITED(status_za_return)){
        status_za_return = WEXITSTATUS(status_za_return);
    }

    return status_za_return;
}

//funkcije vgrajenih ukazov
//####################################################################################

int ni_ukaz(){
    //kakor nop (idejno) samo da na nivoju lupine -- nic se ne izvede (pri simbol je presledek)
    return izhodni_status; //ohrani izhodni status prejsnjega ukaza - ker tole ni dejansko ukaz
}

//Osnovni ukazi

int help(){
    //spremenljivke so globalne tako da ne rabi argumentov
    strcpy(izhodni_izpis, 
        "Osnovni ukazi:\n  help - izpise spisek podprtih ukazov\n  status - izpise izhodni status zadnjega izvedenega ukaza\n  exit <status> - konca lupino s podanim izhodnim statusom\n  name <ime> - nastavi ime lupine\n  print <args> <...> - izpise podane argumente na standardni izhod\n  echo <args> <...> - izpise podane argumente na standardni izhod in skoci v novo vrstico\n  pid - izpise pid lupine\n  ppid - izpiše pid starsa\n\nUkazi za delo z imeniki:\n  dirchange <imenik> - zamenjava trenutnega delovnega imenika (privzeto \"/\"\n  dirwhere - izpis trenutnega delovnega imenika)\n  dirbase - izpis osnove (basename) trenutnega delovnega imenika\n  dirmake <imenik> - ustvarjanje podanega imenika\n  dirremove <imenik> - brisanje podanega imenika\n  dirlist <imenik> - izpis vsebine imenika\n\nUkazi za delo z datotekami:\n  linkhard <cilj> <ime> - ustvarjanje trde povezave na cilj\n  linksoft <cilj> <ime> - ustvarjanje simbolicne povezave na cilj\n  linkread <ime> - izpis cilja podane simbolične povezave\n  linklist <ime> - izpiše vse trde povezave na datoteko z imenom ime (gleda se trenutni delovni imenik)\n  unlink <ime> - brisanje datoteke\n  rename <izvor> <ponor> - preimenovanje datoteke\n  remove <ime> - odstranjevanje datoteke\n  cpcat <izvor> <ponor> - ukaza cp in cat zdruzena\n\nVgrajeni ukazi za info o sistemu in lupini:\n  sysinfo - izpise osnovne informacije v sistemu\n  shellinfo - izpise osnovne informacije o procesu lupine\n\nVgrajeni ukaz za delo s procesi:\n  proc <pot> - nastavitev poti do procfs datotecnega sistema, brez argumenta se izpise nastavljena vrednost\n  pids - izpise PIDe trenutnih procesov\n  pinfo - izpise informacije o trenutnih procesih\n  waitone <pid> - pocaka na otroka s podanim pidom (ce ni podan pocaka enega poljubnega)\n  waitall - pocaka na vse otroke\n\nCevovod:\n  pipes \"<stopnja 1>\" \"<stopnja 2>\" \"<stopnja 3>\" <...>\n\n"
    );
    return 0;
}

int status(){
    sprintf(izhodni_izpis, "%d\n", izhodni_status);
    return 0;
}

int moj_exit(){
    exit(atoi(tokens[1]));
    return 0;
}

int name(){
    if(tokens[1] == NULL){
        strcpy(izhodni_izpis, ime_lupine);
        strcat(izhodni_izpis, "\n");
        return 0;
    }
    int exit_status;
    if(strlen(tokens[1])<=8){
        strcpy(ime_lupine, tokens[1]);
        exit_status = 0;
    }
    else{
        exit_status = 1;
    }
    return exit_status;
}

int print(){
    strcpy(izhodni_izpis, tokens[1]);
    int i = 2;
    while(tokens[i] != NULL){
        strcat(izhodni_izpis, " ");
        strcat(izhodni_izpis, tokens[i++]);
        
    }
    return 0;
}

int echo(){
    if(tokens[1] == NULL){
        printf("\n");
        return 0;
    }
    strcpy(izhodni_izpis, tokens[1]);
    strcat(izhodni_izpis, " ");
    int i = 2;
    while(tokens[i] != NULL){
        strcat(izhodni_izpis, tokens[i++]);
        strcat(izhodni_izpis, " ");
    }
    strcat(izhodni_izpis, "\n");
    return 0;
}

int pid(){
    int pid = getpid();
    sprintf(izhodni_izpis, "%d\n", pid);
    return 0;
}

int ppid(){
    int pid = getppid();
    sprintf(izhodni_izpis, "%d\n", pid);
    return 0;
}

//Ukazi za delo z imeniki

int dirchange(){
    char nov_dir[1000] = {0}; //recimo da ne bo daljsi od 1000
    if(tokens[1]==NULL) strcpy(nov_dir, "/");
    else strcpy(nov_dir,tokens[1]);
    int stat = chdir(nov_dir);
    if(stat == 0) return stat;
    else{
        stat = errno;
        perror("dirchange");
        return stat; 
    }
}

int dirwhere(){
    char pwd[2000] = {0};
    if(getcwd(pwd, sizeof(pwd)) != NULL){
        strcpy(izhodni_izpis, pwd);
        strcat(izhodni_izpis, "\n");
        return 0;
    }
    else return 1;
}

int dirbase(){
    char* dirbasename = basename(getcwd(NULL,0));
    strcpy(izhodni_izpis, dirbasename);
    strcat(izhodni_izpis, "\n");
    return 0;
}

int dirmake(){
    int stat = mkdir(tokens[1], 0755);
    if(stat < 0){
        //ni uspelo - napaka
        stat = errno;
        perror("dirmake");
        return stat;
    }
    return 0;
}

int dirremove(){
    //z rmdir to deluje samo za prazne imenike!!! za neprazne vrne napako!!!
    int stat = rmdir(tokens[1]);
    if(stat < 0){
        //ni uspelo - napaka
        stat = errno;
        perror("dirremove");
        return stat;
    }
    return 0;
}

int dirlist(){
    char pot[1000] = {0}; //bi moglo bit dovolj (famous last words...)
    if(tokens[1] == NULL){
        getcwd(pot,1000);
    }
    else{
        strcpy(pot,tokens[1]);
    }
    int fd_dir = open(pot, O_RDONLY | __O_DIRECTORY);
    int stat;
    if(fd_dir < 0){
        //open ni uspel
        stat = errno;
        perror("dirlist");
        return stat;
    }
    char buf[2000] = {0}; //bi moralo bit dovolj;
    struct linux_dirent* vnos;
    int rezultat = 1; //getdents vrne stevilo prebranih bytov
    
    while(rezultat){
        rezultat = syscall(SYS_getdents, fd_dir, buf, 2000);
        if(rezultat < 0){
            //getdents ni uspel
            stat = errno;
            perror("dirlist");
            return stat;
        }
        int offset = 0;
        while(offset < rezultat){
            vnos = (struct linux_dirent*)(buf + offset);
            strcat(izhodni_izpis, vnos->d_name);
            strcat(izhodni_izpis, "  ");
            offset += vnos->d_reclen;
        }
    }

    strcat(izhodni_izpis, "\n");

    if(close(fd_dir) < 0){
        stat = errno;
        perror("dirlist");
        return stat;
    }

    return 0;
}

//Ukazi za delo z datotekami

int linkhard(){
    int stat;
    stat = link(tokens[1], tokens[2]);
    if(stat < 0){
        stat = errno;
        perror("linkhard");
        return stat;
    }
    else return stat;
}

int linksoft(){
    int stat;
    stat = symlink(tokens[1], tokens[2]);
    if(stat < 0){
        stat = errno;
        perror("linksoft");
        return stat;
    }
    else return stat;
}

int linkread(){
    int stat;
    char pot[1000] = {0};
    int rezultat;

    rezultat = readlink(tokens[1], pot, sizeof(pot));

    if(rezultat < 0){
        //ni blo v redu
        stat = errno;
        perror("linkread");
        return stat;
    }
    else{
        char rezultat_izpis[2000] = {0};
        sprintf(rezultat_izpis, "%s\n", pot);
        strcpy(izhodni_izpis, rezultat_izpis);
    }
}

int linklist(){
    int ret_stat;

    ino_t inode_target;
    struct stat dat_s;
    if(stat(tokens[1], &dat_s) == 0){
        //vse ok
        inode_target = dat_s.st_ino;
    }
    else{
        ret_stat = errno;
        perror("linklist");
        return ret_stat;
    }
    

    char pot[1000] = {0}; //bi moglo bit dovolj (famous last words...)
    getcwd(pot,1000);
    int fd_dir = open(pot, O_RDONLY | __O_DIRECTORY);
    if(fd_dir < 0){
        //open ni uspel
        ret_stat = errno;
        perror("linklist");
        return ret_stat;
    }
    char buf[1000] = {0}; //bi moralo bit dovolj;
    struct linux_dirent* vnos;
    int rezultat = 1; //getdents vrne stevilo prebranih bytov
    
    while(rezultat){
        rezultat = syscall(SYS_getdents, fd_dir, buf, 1000);
        if(rezultat < 0){
            //getdents ni uspel
            ret_stat = errno;
            perror("linklist");
            return ret_stat;
        }
        int offset = 0;
        while(offset < rezultat){
            vnos = (struct linux_dirent*)(buf + offset);
            if(inode_target == vnos->d_ino){
                strcat(izhodni_izpis, vnos->d_name);
                strcat(izhodni_izpis, "  ");
            }
            offset += vnos->d_reclen;
        }
    }

    strcat(izhodni_izpis, "\n");

    if(close(fd_dir) < 0){
        ret_stat = errno;
        perror("linklist");
        return ret_stat;
    }

    return 0;
}

int moj_unlink(){
    int stat;
    stat = unlink(tokens[1]);
    if(stat < 0){
        //yikers bonkers
        stat = errno;
        perror("unlink");
        return stat;
    }
    else return stat;
}

int moj_rename(){
    int stat;
    stat = rename(tokens[1], tokens[2]);
    if(stat < 0){
        //yikers bonkers
        stat = errno;
        perror("unlink");
        return stat;
    }
    else return stat;
}

int moj_remove(){
    int stat;
    stat = remove(tokens[1]);
    if(stat < 0){
        //yikers bonkers
        stat = errno;
        perror("unlink");
        return stat;
    }
    else return stat;
}

int cpcat(){
    int ext_stat;
    int vhod_fd;
    int izhod_fd;
    if(tokens[1] == NULL){
        vhod_fd = 0; //stdin
        izhod_fd = 1;   //stdout
    }
    else{
        if(strcmp(tokens[1],"-") == 0){
            vhod_fd = 0;
        }
        else{
            vhod_fd = open(tokens[1], O_RDONLY);
            if(vhod_fd < 0){
                ext_stat = errno;
                perror("cpcat");
                return ext_stat;
            }
        }
        if(tokens[2] == NULL){
            izhod_fd = 1;
        }
        else{
            izhod_fd = open(tokens[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if(izhod_fd < 0){
                ext_stat = errno;
                perror("cpcat");
                return ext_stat;
            }
        }
    }

    char buffer[1] = {0};
    int st_bytes;
    while(1){
        st_bytes = read(vhod_fd, buffer, 1);
        if(st_bytes == 0){
            ext_stat = st_bytes;
            break;
        }
        else if(st_bytes < 0){
            ext_stat = errno;
            perror("cpcat");
            return ext_stat;
        }
        if(write(izhod_fd, buffer, 1) <= 0){
            ext_stat = errno;
            perror("cpcat");
            return ext_stat;
        }
    }
    if(vhod_fd != 0 && close(vhod_fd) < 0){
        ext_stat = errno;
        perror("cpcat");
        return ext_stat;
    }
    if(izhod_fd != 1 && close(izhod_fd) < 0){
        ext_stat = errno;
        perror("cpcat");
        return ext_stat;
    }
    return ext_stat;
}

//Vgrajeni ukazi za info o sistemu in lupini

int sysinfo(){
    int ext_stat;
    struct utsname sist_info;
    if(uname(&sist_info) < 0){
        //opsala
        ext_stat = errno;
        perror("sysinfo");
        return ext_stat;
    }
    char rezultat[2000] = {0};
    sprintf(rezultat, "Sysname: %s\nNodename: %s\nRelease: %s\nVersion: %s\nMachine: %s\n",
        sist_info.sysname, sist_info.nodename, sist_info. release, sist_info.version, sist_info.machine);
    strcpy(izhodni_izpis, rezultat);
    return 0;
}

int shellinfo(){
    char rezultat[2000] = {0};
    sprintf(rezultat, "Uid: %d\nEUid: %d\nGid: %d\nEGid: %d\n", getuid(), geteuid(), getgid(), getegid());
    //te funkcije so vedno uspesne - ni handlanja napak
    strcpy(izhodni_izpis, rezultat);
    return 0;
}

//Vgrajeni ukaz za delo s proces

int proc(){
    if(tokens[1] == NULL){
        //izpis nastavljene vrednosti
        strcpy(izhodni_izpis, procfs_path);
        strcat(izhodni_izpis, "\n");
        return 0;
    }
    else{
        //sicer pa jo nastavimo
        int ext_status;
        ext_status = access(tokens[1], F_OK | R_OK);
        if(ext_status == 0){
            //ok
            strcpy(procfs_path, tokens[1]);
            return 0;
        }
        else{
            return 1;
        }
    }
}

int pids(){
    int fd_dir = open(procfs_path, O_RDONLY | __O_DIRECTORY);
    int ext_stat;
    if(fd_dir < 0){
        //open ni uspel
        ext_stat = errno;
        perror("pids");
        return ext_stat;
    }
    char buf[2000] = {0}; //bi moralo bit dovolj;
    struct linux_dirent* vnos;
    struct stat stat_vnos;
    int rezultat = 1; //getdents vrne stevilo prebranih bytov
    
    while(rezultat){
        rezultat = syscall(SYS_getdents, fd_dir, buf, 2000);
        if(rezultat < 0){
            //getdents ni uspel
            ext_stat = errno;
            perror("pids");
            return ext_stat;
        }
        int offset = 0;
        while(offset < rezultat){
            vnos = (struct linux_dirent*)(buf + offset);
            if(atoi(vnos->d_name) != 0){
                strcat(izhodni_izpis , vnos->d_name);
                strcat(izhodni_izpis, "\n");
            }
            /* char pot_do_dat[1000] = {0};
            sprintf(pot_do_dat, "%s/%s", procfs_path, vnos->d_name);
            if(stat(pot_do_dat, &stat_vnos) == 0){
                if(S_ISDIR(stat_vnos.st_mode) && atoi(vnos->d_name) != 0){
                    strcat(izhodni_izpis , vnos->d_name);
                    strcat(izhodni_izpis, "\n");
                }
            }
            else{
                ext_stat = errno;
                perror("pids");
                return ext_stat;
            } */
            offset += vnos->d_reclen;
        }
    }

    if(close(fd_dir) < 0){
        ext_stat = errno;
        perror("pids");
        return ext_stat;
    }

    return 0;
}

int pinfo(){
    int ext_stat;
    int fd_dir = open(procfs_path, O_RDONLY | __O_DIRECTORY);
    if(fd_dir < 0){
        //open ni uspel
        ext_stat = errno;
        perror("pinfo");
        return ext_stat;
    }
    char buf[2000] = {0}; //bi moralo bit dovolj;
    struct linux_dirent* vnos;
    struct stat stat_vnos;
    int rezultat = 1; //getdents vrne stevilo prebranih bytov
    
    printf("  PID  PPID STANJE IME\n"); //header izpisa

    while(rezultat){
        rezultat = syscall(SYS_getdents, fd_dir, buf, 2000);
        if(rezultat < 0){
            //getdents ni uspel
            ext_stat = errno;
            perror("pinfo");
            return ext_stat;
        }
        int offset = 0;
        while(offset < rezultat){
            vnos = (struct linux_dirent*)(buf + offset);
            if(atoi(vnos->d_name) != 0){
                char pot_do_dat[1000] = {0};
                sprintf(pot_do_dat, "%s/%s/stat", procfs_path, vnos->d_name);
                int fd_stat_file = open(pot_do_dat, O_RDONLY);
                if(fd_stat_file < 0){
                    ext_stat = errno;
                    perror("pinfo");
                    return ext_stat;
                }
                char buffercek[500] = {0}; //bi moglo bit vec kot dovolj ker nas zanimajo samo znaki na zacetku
                int read_rez = read(fd_stat_file, buffercek, 200);
                if(read_rez < 0){
                    ext_stat = errno;
                    perror("pinfo");
                    return ext_stat;
                }
                int pid; char ime[450] = {0}; char stanje; int ppid;
                sscanf(buffercek, "%d (%s %c %d", &pid, ime, &stanje, &ppid);
                char obrezano_ime[450] = {0};
                strncpy(obrezano_ime,ime,strlen(ime)-1);
                printf("%5d %5d %6c %s\n", pid, ppid, stanje, obrezano_ime);
            }
            /* char pot_do_dat[1000] = {0};
            sprintf(pot_do_dat, "%s/%s", procfs_path, vnos->d_name);
            if(stat(pot_do_dat, &stat_vnos) == 0){
                if(S_ISDIR(stat_vnos.st_mode) && atoi(vnos->d_name) != 0){
                    char pot_do_dat[1000] = {0};
                    sprintf(pot_do_dat, "%s/%s/stat", procfs_path, vnos->d_name);
                    int fd_stat_file = open(pot_do_dat, O_RDONLY);
                    if(fd_stat_file < 0){
                        ext_stat = errno;
                        perror("pinfo");
                        return ext_stat;
                    }
                    char buffercek[500] = {0}; //bi moglo bit vec kot dovolj ker nas zanimajo samo znaki na zacetku
                    int read_rez = read(fd_stat_file, buffercek, 200);
                    if(read_rez < 0){
                        ext_stat = errno;
                        perror("pinfo");
                        return ext_stat;
                    }
                    int pid; char ime[450] = {0}; char stanje; int ppid;
                    sscanf(buffercek, "%d %s %c %d", &pid, ime, &stanje, &ppid);
                    printf("%5d %5d %6c %s\n", pid, ppid, stanje, ime);
                }
            }
            else{
                ext_stat = errno;
                perror("pinfo");
                return ext_stat;
            } */
            
            offset += vnos->d_reclen;
        }
    }

    if(close(fd_dir) < 0){
        ext_stat = errno;
        perror("pinfo");
        return ext_stat;
    }

    return 0;
}

int waitone(){
    //kolikor jaz razberem iz navodil nas tukaj ne zanima izhodni status otroka
    int ext_stat;
    if(tokens[1] == NULL){
        if(wait(NULL) < 0){
            ext_stat = errno;
            perror("waitone");
            return ext_stat;
        }
    }
    else{
        if(waitpid(atoi(tokens[1]), NULL, 0) < 0){
            ext_stat = errno;
            perror("waitone");
            return ext_stat;
        }
    }
    return 0;
}

int waitall(){
    //tudi tukaj ni videti da nas zanimajo izhodni statusi otrok
    while(waitpid(-1, NULL, 0) > 0){
        continue;
    }
    return 0;
}

//Cevovod

//pomozne funkcije za cevovod
int izvajanje_ukaza_v_cevovodu(int st_stopnje){
    //ker se bo klicalo samo v otroku, lahko povozi prejsnje stvari


    sprintf(line, "%s", tokens[st_stopnje+1]);
    //sprintf da terminira z \0
    // +1 zato ker prvi token je "pipes"

    *izhodni_izpis = NULL;
    preusmeritev_izhoda = 0;
    preusmeritev_vhoda = 0;

    token_count = tokenize(line, tokens);
    int st_ukaza = ukaz_lookup();

    izhodni_status = tabela_kazalcev_funkcij_ukazov[st_ukaza]();
    printf("%s",izhodni_izpis);

}

int zacetna_stopnja(int ta_stopnja){

    pipe(tabela_cevi[ta_stopnja]);
    fflush(stdin);
    if(!fork()){
        //prva stopnja
        dup2(tabela_cevi[ta_stopnja][1], 1); //izhod te stopnje preusmerimo v cev
        close(tabela_cevi[ta_stopnja][0]); //ne rabimo vec
        close(tabela_cevi[ta_stopnja][1]);
        
        izvajanje_ukaza_v_cevovodu(ta_stopnja);

        exit(izhodni_status);
    }
    else{
        close(tabela_cevi[ta_stopnja][1]);
    }

}

int sredinska_stopnja(int ta_stopnja){

    //int ta_stopnja = naslednja_stopnja_cevovoda++;
    pipe(tabela_cevi[ta_stopnja]);
    fflush(stdin);
    if(!fork()){
        //neka vmesna stopnja
        dup2(tabela_cevi[ta_stopnja-1][0], 0); //izhod prejsnje cevi preusmerimo na vhod te stopnje
        dup2(tabela_cevi[ta_stopnja][1], 1); //izhod te stopnje damo v ta novo cev
        close(tabela_cevi[ta_stopnja-1][0]);
        close(tabela_cevi[ta_stopnja-1][1]);
        close(tabela_cevi[ta_stopnja][0]);
        close(tabela_cevi[ta_stopnja][1]);

        izvajanje_ukaza_v_cevovodu(ta_stopnja);

        exit(izhodni_status);

    }
    else{
        //stars
        close(tabela_cevi[ta_stopnja-1][0]); //zapremo prejsnjo cev
        close(tabela_cevi[ta_stopnja-1][1]);
        close(tabela_cevi[ta_stopnja][0]);
        close(tabela_cevi[ta_stopnja][1]);
    }

}

int koncna_stopnja(int ta_stopnja){

    //int ta_stopnja = naslednja_stopnja_cevovoda++;
    fflush(stdin);
    if(!fork()){
        //zadnja stopnja
        dup2(tabela_cevi[ta_stopnja-1][0], 0); //izhod prejsnje cevi na vhod te stopnje
        close(tabela_cevi[ta_stopnja-1][0]);
        close(tabela_cevi[ta_stopnja-1][1]);

        izvajanje_ukaza_v_cevovodu(ta_stopnja);

        exit(izhodni_status);
    }
    else{
        //stars
        close(tabela_cevi[ta_stopnja-1][0]);
        //pocakamo vse stopnje razen zadnje
        for(int i=0; i < stevilo_stopenj-1; i++){
            wait(NULL);
        }

        //za zadnjo polovimo status
        int ext_stat;
        waitpid(-1, &ext_stat, 0);
        if(WIFEXITED(ext_stat)){
            ext_stat = WEXITSTATUS(ext_stat);
        }
 
        izhodni_status = ext_stat;

    }
}
//

int pipes(){
    
    naslednja_stopnja_cevovoda = 0;

    stevilo_stopenj = token_count - 1; // -1 za "pipes"

   // int test1;
    //int test2;
    //test1 = dup(STDOUT_FILENO);
    //test2 = dup(STDIN_FILENO);

    for(int s = 0; s < stevilo_stopenj; s++){
        if(s==0) zacetna_stopnja(s);
        else if(s==stevilo_stopenj-1) koncna_stopnja(s);
        else sredinska_stopnja(s);
    }
    
    //dup2(test1, STDERR_FILENO);
    //dup2(test2, STDIN_FILENO);

    return 0;
}

//####################################################################################
// --funkcije vgrajenih ukazov


void rokovalnik_za_zombije(int signum){
    int pid;
    int ext_status;
    while(1){
        pid = waitpid(-1, &ext_status, WNOHANG); //obvezno nohang da ne blokira
        if(pid <= 0) break;
        ext_status = WEXITSTATUS(ext_status);
    }
}


int main(){
    
    signal(SIGCHLD, rokovalnik_za_zombije);

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    if(isatty(0)){
        nacin = 1;
    }
    else{
        nacin = 0;
    }

    // REPL

    while(1){

        //init
        *izhodni_izpis = NULL;
        preusmeritev_izhoda = 0;
        preusmeritev_vhoda = 0;

        //izpis poziva
        if(nacin) printf("%s> ", ime_lupine);
        
        //read
        if(fgets(line, 1000, stdin) == NULL){
            //EOF!
            break;
        };
        fflush(stdin);

        //eval
        token_count = tokenize(line, tokens);
        int indeks_ukaza = ukaz_lookup();

        if(token_count > 0 && strcmp(tokens[token_count-1], "&") == 0){
            //izvajanje v ozadju!

            tokens[--token_count] = NULL;

            int fork_pid = fork();
            if(fork_pid < 0){
                izhodni_status = errno;
                perror("izvajanje v ozadju");
            }
            else if(fork_pid == 0){
                ///otrok
                if(preusmeritev_izhoda){
                    int p_i_fd = open(preusmerjen_izhod, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if(p_i_fd < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    if(dup2(p_i_fd, 1) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    if(close(p_i_fd) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    preusmeritev_izhoda = 0;
                }
                if(preusmeritev_vhoda){
                    int p_v_fd = open(preusmerjen_vhod, O_RDONLY);
                    if(p_v_fd < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    if(dup2(p_v_fd, 0) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    if(close(p_v_fd) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                        exit(izhodni_status);
                    }
                    preusmeritev_vhoda = 0;
                }
                izhodni_status = tabela_kazalcev_funkcij_ukazov[indeks_ukaza]();
                printf("%s",izhodni_izpis);
                exit(izhodni_status);
            }
            else{
                //koda starsa
            }
        }
        else{
            //izvajanje v ospredju
            if(indeks_ukaza != 31){
                //ce ni zunanji ukaz
                // (ce je, samo v otroku prevezemo deskriptorje in se ne sekiramo)
                if(preusmeritev_izhoda){
                    stdout_kopija = dup(STDOUT_FILENO);
                    if(stdout_kopija < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                    }
                    int p_i_fd = open(preusmerjen_izhod, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if(p_i_fd < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                    }

                    if(dup2(p_i_fd, 1) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                    }
                    if(close(p_i_fd) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev izhoda");
                    }
                    preusmeritev_izhoda = 2;
                }
                if(preusmeritev_vhoda){
                    stdin_kopija = dup(STDIN_FILENO);
                    if(stdin_kopija < 0){
                        izhodni_status = errno;
                        perror("preusmeritev vhoda");
                    }
                    int p_v_fd = open(preusmerjen_vhod, O_RDONLY);
                    if(p_v_fd < 0){
                        izhodni_status = errno;
                        perror("preusmeritev vhoda");
                    }
                    if(dup2(p_v_fd, 0) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev vhoda");
                    }
                    if(close(p_v_fd) < 0){
                        izhodni_status = errno;
                        perror("preusmeritev vhoda");
                    }
                    preusmeritev_vhoda = 2;
                }
            }
            izhodni_status = tabela_kazalcev_funkcij_ukazov[indeks_ukaza]();
            printf("%s",izhodni_izpis);

            //restore fd ce je bila preusmeritev
            if(preusmeritev_izhoda == 2){
                if(dup2(stdout_kopija, STDOUT_FILENO) < 0){
                    izhodni_status = errno;
                    perror("preusmeritev izhoda");
                }
                if(close(stdout_kopija) < 0){
                    izhodni_status = errno;
                    perror("preusmeritev izhoda");
                }
                preusmeritev_izhoda = 0;
            }
            if(preusmeritev_vhoda == 2){
                if(dup2(stdin_kopija, STDIN_FILENO) < 0){
                    izhodni_status = errno;
                    perror("preusmeritev vhoda");
                }
                if(close(stdin_kopija) < 0){
                    izhodni_status = errno;
                    perror("preusmeritev vhoda");
                }
                preusmeritev_vhoda = 0;
            }
        }
        

    } //loop {while 1}

    // -REPL


    return 0;
}