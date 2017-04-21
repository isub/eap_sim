/* tcp_client_connect connects to remote tcp-server */
/* return value is a socket descriptor */
int tcp_client_connect (const char *p_pszHostName, unsigned short p_usPort);

/* tcp_client_send sends a data block */
int tcp_client_send (int p_iSock, const char *p_mcBuf, int p_iLen);

/* tcp_client_recv receives a data block */
/* return value is a number of bytes was sent */
int tcp_client_recv (int p_iSock, char *p_mcBuf, int p_iBufSize);
