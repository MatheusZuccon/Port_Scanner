// port_scanner.c
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define DEFAULT_TIMEOUT_SEC 1

// tenta conectar ao host:port com timeout (segundos).
// retorna:  1 => open, 0 => closed (connect failed), -1 => timeout or error
int try_connect_with_timeout(struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int sock = -1;
    int flags, ret, err;
    socklen_t len;
    fd_set wfds;
    struct timeval tv;

    // cria socket com o mesmo family e tipo do addr
    sock = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    // set non-blocking
    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) { close(sock); return -1; }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) { close(sock); return -1; }

    ret = connect(sock, addr, addrlen);
    if (ret == 0) {
        // connect imediato (normal em localhost)
        close(sock);
        return 1;
    }

    if (errno != EINPROGRESS) {
        // erro imediato (porta fechada)
        close(sock);
        return 0;
    }

    // aguarda até timeout usando select()
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (ret == 0) {
        // timeout
        close(sock);
        return -1;
    } else if (ret < 0) {
        // erro select
        close(sock);
        return -1;
    } else {
        // verificar SO_ERROR
        len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
            close(sock);
            return -1;
        }
        if (err == 0) {
            close(sock);
            return 1; // conectado
        } else {
            close(sock);
            return 0; // recusado / fechado
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "Uso: %s <host> <start_port> <end_port> <output_file> [timeout_sec]\n"
            "Ex: %s 127.0.0.1 20 1024 results.txt 1\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    const char *outfile = argv[4];
    int timeout_sec = (argc >= 6) ? atoi(argv[5]) : DEFAULT_TIMEOUT_SEC;
    if (start_port <= 0 || end_port <= 0 || end_port < start_port) {
        fprintf(stderr, "Faixa de portas inválida.\n");
        return 1;
    }
    if (timeout_sec <= 0) timeout_sec = DEFAULT_TIMEOUT_SEC;

    // resolver host (getaddrinfo)
    struct addrinfo hints, *res, *rp;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC; // suporta IPv4 e IPv6

    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "Erro getaddrinfo: %s\n", gai_strerror(gai));
        return 1;
    }

    // abre arquivo para escrita (append)
    FILE *f = fopen(outfile, "w");
    if (!f) {
        perror("fopen output file");
        freeaddrinfo(res);
        return 1;
    }

    fprintf(f, "Port scan results for %s (ports %d-%d), timeout=%ds\n", host, start_port, end_port, timeout_sec);
    fprintf(f, "------------------------------------------------------------\n");
    printf("Scanning %s ports %d..%d (timeout %ds) — results saved in %s\n", host, start_port, end_port, timeout_sec, outfile);

    // Para cada entry de getaddrinfo (prefere IPv4/IPv6)
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        // a estrutura base sem porta; faremos copiar e ajustar porta por iteração
        int family = rp->ai_family;

        // converte endereço base para string só para header (opcional)
        void *addrptr = NULL;
        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)rp->ai_addr;
            addrptr = &(sa->sin_addr);
            inet_ntop(family, addrptr, ipstr, sizeof(ipstr));
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)rp->ai_addr;
            addrptr = &(sa6->sin6_addr);
            inet_ntop(family, addrptr, ipstr, sizeof(ipstr));
        } else {
            continue;
        }

        fprintf(f, "Scanning address: %s\n", ipstr);
        printf("Using address %s\n", ipstr);

        // var para armazenar sockaddr mutável
        for (int port = start_port; port <= end_port; ++port) {
            // copiar o addrinfo->ai_addr para uma struct local e setar porta
            if (family == AF_INET) {
                struct sockaddr_in dest;
                memcpy(&dest, rp->ai_addr, rp->ai_addrlen);
                dest.sin_port = htons(port);

                int r = try_connect_with_timeout((struct sockaddr *)&dest, sizeof(dest), timeout_sec);
                if (r == 1) {
                    printf("Port %5d: OPEN\n", port);
                    fprintf(f, "Port %5d: OPEN\n", port);
                } else if (r == 0) {
                    printf("Port %5d: CLOSED\n", port);
                    fprintf(f, "Port %5d: CLOSED\n", port);
                } else {
                    printf("Port %5d: TIMEOUT/ERROR\n", port);
                    fprintf(f, "Port %5d: TIMEOUT/ERROR\n", port);
                }
            } else if (family == AF_INET6) {
                struct sockaddr_in6 dest6;
                memcpy(&dest6, rp->ai_addr, rp->ai_addrlen);
                dest6.sin6_port = htons(port);

                int r = try_connect_with_timeout((struct sockaddr *)&dest6, sizeof(dest6), timeout_sec);
                if (r == 1) {
                    printf("Port %5d: OPEN\n", port);
                    fprintf(f, "Port %5d: OPEN\n", port);
                } else if (r == 0) {
                    printf("Port %5d: CLOSED\n", port);
                    fprintf(f, "Port %5d: CLOSED\n", port);
                } else {
                    printf("Port %5d: TIMEOUT/ERROR\n", port);
                    fprintf(f, "Port %5d: TIMEOUT/ERROR\n", port);
                }
            }
            fflush(f);
        } // for ports

        // se o endereço foi testado e gerou resultados, podemos escolher não testar outros addresses
        // mas deixei para testar todos. Se quiser testar só o primeiro address, descomente:
        // break;
    }

    freeaddrinfo(res);
    fclose(f);

    printf("Scan completo. Resultados gravados em %s\n", outfile);
    return 0;
}
