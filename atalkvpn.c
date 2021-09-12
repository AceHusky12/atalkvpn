/*-
 * Copyright (c) 2021 Nathanial Sloss <nathanialsloss@yahoo.com.au>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Portions of the aarp code were from the NetBSD appletalk stack.
 * See: src/sys/netatalk for more information.
 */

/*
 * Copyright (c) 1990,1991 Regents of The University of Michigan.
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation, and that the name of The University
 * of Michigan not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission. This software is supplied as is without expressed or
 * implied warranties of any kind.
 *
 * This product includes software developed by the University of
 * California, Berkeley and its contributors.
 *
 *	Research Systems Unix Group
 *	The University of Michigan
 *	c/o Wesley Craig
 *	535 W. William Street
 *	Ann Arbor, Michigan
 *	+1-313-764-2278
 *	netatalk@umich.edu
 */

/* This program allows appletalk phase 1 packets to be tunneled via a udp
 * port to a tap(4) for use with Bob Braun's tunneling software (which
 * requires appletalk 58 or higher.  Confirmed working with netatalk22 on
 * NetBSD with a Macintosh Plus running system 6.0.8 file sharing and printing
 * are supported.  For Mr Braun's extension and sources see: 
 *
 * https://web.archive.org/web/20160115003115if_/http://www.synack.net/~bbraun/macsrc/avpn0.4.9.1.cpt.hqx
 *
 */

#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/ethertypes.h>
#include <net/if_arp.h>
#include <net/if_ether.h>
#include <netinet/in.h>
#include <netatalk/at.h>
#include <netatalk/aarp.h>
#include <netatalk/ddp.h>

#include <errno.h>
#include <err.h>

#include <netdb.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

int	local_listen(char *, char *, struct addrinfo);
void	usage(void);
void	send_probe_resp(int, uint8_t, uint8_t);
u_short at_cksum(u_char *data, int len, int skip);

unsigned char *buff, *outbuff;

extern uint32_t ether_crc32_le(const uint8_t *, size_t);

const uint16_t LLDAPSTR = { 0xfed1 };

unsigned char atalkaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char myatalkaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t snet[2] = { 0x00, 0x01 };
uint8_t tnet[2] = { 0x00, 0x01 };

struct ether_header *eh;
struct ether_aarp *ea;

#ifdef DEBUG
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...) 
#endif

#define BUFF_SZ (65 * 1024)

void
send_probe_resp(int fd, uint8_t mynode, uint8_t srcnode)
{

	DEBUG_LOG("AARP\n");
	memset(outbuff, 0, BUFF_SZ + 2);
	eh = (struct ether_header *) outbuff;
	ea = (struct ether_aarp *) (outbuff + sizeof(struct ether_header));
        memcpy(eh->ether_dhost, atalkaddr, sizeof(eh->ether_dhost));	
        memcpy(eh->ether_shost, myatalkaddr, sizeof(eh->ether_shost));	
	memcpy(ea->aarp_tha, atalkaddr, sizeof(ea->aarp_sha));
	memcpy(ea->aarp_sha, myatalkaddr, sizeof(ea->aarp_sha));

	eh->ether_type = htons(ETHERTYPE_AARP);
        ea->aarp_tpnode = srcnode;
        ea->aarp_spnode = mynode;
	memcpy(ea->aarp_spnet, snet, sizeof(snet));
	memcpy(ea->aarp_tpnet, tnet, sizeof(tnet));
        ea->aarp_op = htons(AARPOP_RESPONSE);
	ea->aarp_hln = 6;
	ea->aarp_pln = 4;
	ea->aarp_hrd = htons(ARPHRD_ETHER);
	ea->aarp_pro = htons(ETHERTYPE_APPLETALK);
	write(fd, outbuff, sizeof(*eh) + sizeof(*ea));

}

u_short
at_cksum(u_char *data, int len, int skip)
{
        u_char         *end = data + len;
        u_long          cksum = 0;

        for (; data < end; data++) {
       		if (skip) {
                	skip--;
                        continue;
                }
                cksum = (cksum + *data) << 1;
                if (cksum & 0x00010000)
                      cksum++;
                cksum &= 0x0000ffff;
        }

        if (cksum == 0) {
                cksum = 0x0000ffff;
        }
	return (u_short)cksum;
}

int
main (int argc, char* argv[])
{
	struct addrinfo hints;
	int authme = 0, commsock, new_conn, connlen, mydata, nr, tapdev;
	unsigned char magic[12]= { 0, 5, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
	struct timeval lasttime, timenow;
	int ch, notimeout = 0, skip = 0;
	char mytap[255], myport[255] = "1029";

	while ((ch = getopt(argc, argv, "i:p:n")) !=
	    EOF) {
		switch (ch) {
		case 'p':
			strncpy(myport, optarg, sizeof(myport));
			break;
		case 'i':
			strncpy(mytap, optarg, sizeof(mytap));
			break;
		case 'n':
			notimeout = 1;
			break;
		default:
			usage();
		}
	}
	argv += optind;
	argc -= optind;

	if (argc)
		usage();
	if (!strlen(mytap))
		usage();


	buff = malloc(BUFF_SZ);
	if (buff == NULL) {
		err(errno, "cannot allocate buffer\n");
	}

	outbuff = malloc(BUFF_SZ+2);
	if (outbuff == NULL) {
		free(buff);
		err(errno, "cannot allocate output buffer\n");
	}
#ifndef DEBUG
	if (daemon(0, 1) == -1) {
		free(outbuff);
		free(buff);
		errx(EXIT_FAILURE, "daemon");
	}
	pidfile("/var/run/atalkvpnd.pid");
#endif

	for (;;) {
	if ((tapdev = open(mytap, O_RDWR|O_NONBLOCK)) < 0) {
		free(outbuff);
		free(buff);
		errx(errno, "cannot open tap device %s", mytap);
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	commsock = local_listen(NULL, myport, hints);
	struct sockaddr_storage z;

        int len = sizeof(z);
        int plen = 2048;
        while ((nr = recvfrom(commsock, buff, plen, MSG_PEEK,
            (struct sockaddr *)&z, &len)) < 0 && errno == EAGAIN)
		usleep(100000);
        if (nr < 0)
              errx(1, "recvfrom");

        nr = connect(commsock, (struct sockaddr *)&z, len);
       if (nr < 0)
       		errx(1, "connect");
	gettimeofday(&lasttime, NULL);
	timenow = lasttime;

	while (1) {

		gettimeofday(&timenow, NULL);
		if (!notimeout && (timenow.tv_sec > lasttime.tv_sec + 240))
			goto next;

		while (ioctl(commsock, FIONREAD, &mydata) == -1) {
		};

		if ((mydata > 0) && ((nr = read(commsock, buff, BUFF_SZ)) !=
		    -1) && (nr != 0)) {
			switch (buff[1]) {
			case 5:
				if (authme == 0) {
					DEBUG_LOG("Auth attempt\n");
					write(commsock, magic, sizeof(magic));
					lasttime = timenow;
					authme++;
					continue;
				} else {
					DEBUG_LOG("Authenticated\n");
					buff[0] = 0;
					write(commsock, buff, 1);
					lasttime = timenow;
					authme++;
					continue;
				}
				break;
			case 3:		/* De auth */
				goto next;
				break;
			case 4:
				lasttime = timenow;
				break;
			case 1:
				lasttime = timenow;
				buff[3] = 36;
				write(commsock, buff, 3);
				break;
			case 2:
				if (authme != 3)
					break;
				memcpy(myatalkaddr, buff + 4, sizeof(myatalkaddr));
				memcpy(outbuff, atalkaddr, sizeof(atalkaddr));

				nr -= 4;
				memcpy(outbuff + 6, buff + 4, nr);
				nr += 6;
				eh = (struct ether_header *)outbuff;
				eh->ether_type = htons(ETHERTYPE_APPLETALK);

				struct elaphdr *el = (struct elaphdr *)
				    (outbuff + ETHER_HDR_LEN);
				DEBUG_LOG("DDP: %x\n", el->el_type);
				if (el->el_type == ELAP_DDPEXTEND) {
					u_short crc = at_cksum(&el->el_type +						    1, nr - 17, 4);
					DEBUG_LOG("CRC %x\n",crc);
					outbuff[19] = (crc & 0xff00) >> 8;
					outbuff[20] = crc & 0xff;
				}
				if (write(tapdev, outbuff, nr) != nr) {
					DEBUG_LOG("connection lost\n");
					goto next;
				}
				lasttime = timenow;
				DEBUG_LOG("Read %d bytes\n", nr);
				skip = 1;
				break;
			default:
				DEBUG_LOG("Unhandled case %d\n", buff[1]);
			}
		}

		while (ioctl(tapdev, FIONREAD, &mydata) == -1) {
		};

		if ((mydata > 0) && ((nr = read(tapdev, buff, BUFF_SZ)) != -1)
		    && (nr != 0)) {
			if (buff[0] == 0x33 && buff[1] == 0x33) {
				memcpy(atalkaddr, buff + 6, sizeof(atalkaddr));
				lasttime = timenow;
				DEBUG_LOG("Authenticated\n");
				lasttime = timenow;
				authme++;
				write(commsock, outbuff, 3);

				continue;
			}

			struct ether_header *eh = (struct ether_header *)buff;

			if (eh->ether_type == ntohs(ETHERTYPE_AARP)) {
				struct ether_aarp *ea;
				ea = (struct ether_aarp *)(buff + sizeof(*eh));
				if (strcmp(ea->aarp_spnet, snet) == 0)
					send_probe_resp(tapdev, ea->aarp_tpnode,
					    ea->aarp_spnode);
				lasttime = timenow;
				continue;
			}
			if (authme != 3)
				continue;
			if (eh->ether_type != ntohs(ETHERTYPE_APPLETALK)) {
				DEBUG_LOG("NOT AN APPLETALK PACKET\n");
				continue;
			}
			eh->ether_type = htons(LLDAPSTR);

			memset(outbuff, 0, BUFF_SZ + 2);
			outbuff[0] = 0x00;
			outbuff[1] = 0x02;
			nr -= 4;
			memcpy(outbuff + 2, buff + 4, nr);
			nr += 2;

			if (write(commsock, outbuff, nr) != nr ) {
				DEBUG_LOG("connection lost %d\n",errno);
				goto next;
			} 
			lasttime = timenow;
			DEBUG_LOG("Wrote %d bytes\n", nr);
			skip = 1;
		}
		memset (buff, 0, BUFF_SZ);
		if (!skip)
			usleep(10000);
		skip = 0;
	}

next:
	authme = 0;
	close(commsock);
	close(tapdev);
	}

	return EXIT_SUCCESS;
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
int
local_listen(char *host, char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	int s = -1, ret, x = 1, save_errno;
	int error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	if (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	if ((error = getaddrinfo(host, port, &hints, &res0)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol)) < 0)
			continue;

		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
		if (ret == -1)
			errx(1, NULL);


		if (bind(s, (struct sockaddr *)res->ai_addr,
		    res->ai_addrlen) == 0)
			break;

		save_errno = errno;
		close(s);
		errno = save_errno;
		s = -1;
	}

	freeaddrinfo(res0);

	return (s);
}

void
usage()
{
	errx(EXIT_FAILURE, "usage: %s [-n] [-p port] -i tapdev", getprogname());
}

