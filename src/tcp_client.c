#include "tcp_client.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <errno.h>

int tcp_client_connect (const char *p_pszHostName, unsigned short p_usPort)
{
	int iSock = -1;
	int iFnRes;
	struct sockaddr_in soSockAddr;
	struct hostent *psoHostEnt;

	do {
		/* open socket */
		iSock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (-1 == iSock) {
			/* if error occurred */
			break;
		}

		memset (&soSockAddr, 0, sizeof(soSockAddr));

		/* determine host ip-address */
		psoHostEnt = gethostbyname (p_pszHostName);
		if (psoHostEnt) {
			soSockAddr.sin_addr.s_addr = *((in_addr_t*)(psoHostEnt->h_addr_list[0]));
			soSockAddr.sin_family = psoHostEnt->h_addrtype;
		} else {
			soSockAddr.sin_addr.s_addr = inet_addr (p_pszHostName);
			soSockAddr.sin_family = AF_INET;
		}

		/* connect to remote host */
		soSockAddr.sin_port = htons (p_usPort);
		soSockAddr.sin_family = AF_INET;
		iFnRes = connect (iSock, (struct sockaddr*)&soSockAddr, sizeof(soSockAddr));
		if (-1 == iFnRes) {
			/* if error occurred */
			close (iSock);
			iSock = -1;
			break;
		}
	} while (0);

	return iSock;
}

int tcp_client_send (int p_iSock, const char *p_mcBuf, int p_iLen)
{
	int iRetVal = 0;
	int iFnRes;
	int iSent;

	do {
		iSent = 0;
		struct pollfd msoPollFd[1];

		msoPollFd[0].fd = p_iSock;
		msoPollFd[0].events = POLLOUT;

		/* wait for write data */
		iFnRes = poll (msoPollFd, 1, 5000);
		/* check wait result */
		switch (iFnRes) {
		case 0: /* time out */
			iRetVal = -10;
			break;
		case -1: /* error occurred while poll processed */
			iRetVal = -1;
			break;
		case 1: /* some evet occurred */
			if (0 == (POLLOUT & (msoPollFd[0].revents))) {
				/* socket is not ready to perform write operation */
				iRetVal = -20;
			}
			break;
		default:
			iRetVal = -30;
			break;
		}
		if (-1 == iRetVal) {
			/* when any error accurred */
			break;
		}

		while (iSent < p_iLen) {
			iFnRes = send (p_iSock, p_mcBuf, p_iLen - iSent, 0);
			if (-1 == iFnRes) {
				iRetVal = -1;
				break;
			} else {
			}
			iSent += iFnRes;
		}
	} while (0);

	return iRetVal;
}

int tcp_client_recv (int p_iSock, char *p_mcBuf, int p_iBufSize)
{
	int iRetVal = 0;
	int iFnRes;

	do {
		struct pollfd msoPollFd[1];

		msoPollFd[0].fd = p_iSock;
		msoPollFd[0].events = POLLIN;

		/* wait for read data */
		iFnRes = poll (msoPollFd, 1, 5000);
		/* check wait result */
		switch (iFnRes) {
		case 0: /* time out */
			iRetVal = -10;
			break;
		case -1: /* error occurred while poll processed */
			iRetVal = -1;
			break;
		case 1: /* some evet occurred */
			if (0 == (POLLIN & (msoPollFd[0].revents))) {
				/* socket is not ready to perform read operation */
				iRetVal = -20;
			}
			break;
		default:
			iRetVal = -30;
			break;
		}
		if (0 > iRetVal) {
			/* when any error accurred */
			break;
		}

		iFnRes = recv (p_iSock, p_mcBuf, p_iBufSize, 0);
		if (0 == iFnRes) {
			/* connection is closed by peer */
			iRetVal = 0;
			break;
		}
		if (-1 == iFnRes) {
			/* error occurred */
			iRetVal = -1;
			break;
		}
		/* success */
		iRetVal = iFnRes;
	} while (0);

	return iRetVal;
}
