/*
 * rlm_auc_drv.c
 *
 * Version:  $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2013  Sabir Izrafilov <SubBeer@gmail.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/conffile.h>

#include "../rlm_eap/libeap/eap_sim.h"

#include <stdlib.h>
#include "CoACommon.h"
#include "ss7gw_drv.h"
#include "pspacket.h"
#include "tcp_client.h"

#define IMSI_VALUE_LENGTH 15
//#define SS7GW_SERVER "172.27.25.105"
#define SS7GW_SERVER "172.27.25.97"
#define SS7GW_PORT "5100"

static void add_reply_message(REQUEST *request, const char *p_pszReplyMessage)
{
  VALUE_PAIR *vp;

  vp = paircreate (18, PW_TYPE_STRING);
  pairparsevalue (vp, p_pszReplyMessage);
  pairadd (&request->reply->vps, vp);
}

static int extract_IMSI(REQUEST *request, char *p_mcIMSI, size_t p_stBufSize)
{
  if(IMSI_VALUE_LENGTH <= p_stBufSize) {
    /* Ok */
  } else {
    add_reply_message(request, "not enough buffer size");
		radlog_request(L_AUTH, 0, request, "not enough buffer size\n");
		return 100;
  }

	if (NULL != request->username) {
    /* Ok */
  } else{
    add_reply_message(request, "empty User-Name attribute");
		radlog_request(L_AUTH, 0, request, "Attribute 'User-Name' is required for authentication\n");
		return 101;
	}

  /* check user-name type */
  if(request->username->vp_strvalue[0] == '1') {
    /* Ok */
  } else {
    add_reply_message(request, "Invalid user name");
		RDEBUG("ERROR: Invalid user name");
    return 102;
  }

  /* check user-name format */
  /* 1250270700283220@wlan.mnc027.mcc250.3gppnetwork.org */
  if('@' == request->username->vp_strvalue[IMSI_VALUE_LENGTH+1]) {
    /* Ok */
  } else {
    add_reply_message(request, "Invalid user name");
		RDEBUG("ERROR: Invalid user name");
    return 103;
  }
  if(0 == strncmp("3gppnetwork.org", &(request->username->vp_strvalue[request->username->length - 15]), 15)) {
    /* Ok */
  } else {
    add_reply_message(request, "Invalid user name");
		RDEBUG("ERROR: Invalid user name");
    return 104;
  }

	/* extract IMSI from user-name */
  memcpy(p_mcIMSI, &(request->username->vp_strvalue[1]), IMSI_VALUE_LENGTH);

  return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
int get_triplets(REQUEST *request)
{
	VALUE_PAIR *vp;
	char mcIMSI[IMSI_VALUE_LENGTH];

	/* quiet the compiler */
	request = request;

	RDEBUG ("check Auth-Type");
	vp = pairfind (request->config_items, PW_AUTH_TYPE);
	if (vp) {
		RDEBUG ("Auth-Type is: '%s'", vp->vp_strvalue);
		if (strcmp (vp->vp_strvalue, "EAP")) {
			return 201;
		}
	} else {
		return 202;
	}

  if(0 == extract_IMSI(request, mcIMSI, sizeof(mcIMSI))) {
    /* Ok */
  } else {
    return 203;
  }

	/* test zone ***************************************************************/
	int iFnRes;
	struct SPSPackHolder soPSPackHolder;
	char mcDescr[0x100];
	int iSock = -1;
  char mcReplyMessage[128];

	do {
		char mcBuf[0x200];
		unsigned short usPackLen;

		RDEBUG ("try to initialize PS packet");
		memset (&soPSPackHolder, 0, sizeof (soPSPackHolder));
		iFnRes = pspack_init (&soPSPackHolder, 0, SS7GW_IMSI_REQ);
		if (0 == iFnRes) {
      /* Ok */
    } else {
      add_reply_message(request, "can not initialize PS packet");
			RDEBUG("can not initialize PS packet");
			break;
		}
		RDEBUG("try to add an attribute to PS packet");
		iFnRes = pspack_add_attrtopack (&soPSPackHolder, SS7GW_IMSI, IMSI_VALUE_LENGTH, mcIMSI);
		if (0 == iFnRes) {
      /* Ok */
    } else {
			add_reply_message(request, "can not add SS7GW_IMSI attribute to PS packet");
			RDEBUG("can not add SS7GW_IMSI attribute to PS packet");
			break;
		}
		iFnRes = pspack_add_attrtopack (&soPSPackHolder, SS7GW_TRIP_NUM, 1, "3");
		if (0 == iFnRes) {
      /* Ok */
    } else {
			add_reply_message(request, "can not add SS7GW_TRIP_NUM attribute to PS packet");
			RDEBUG ("can not add SS7GW_TRIP_NUM attribute to PS packet");
			break;
		}
		usPackLen = soPSPackHolder.m_soPackHdr.m_usPackLen;
		RDEBUG ("try to fill buffer: packet size: %d", usPackLen);
		iFnRes = pspack_fill_buf ((struct SPSRequest*)mcBuf, sizeof (mcBuf), &soPSPackHolder);
		if (0 == iFnRes) {
      /* Ok */
			int i;
			for (i = 0; i < usPackLen; i += 8) {
				RDEBUG ("PS packet dump: %02x%02x%02x%02x%02x%02x%02x%02x",
					mcBuf[i],mcBuf[i+1],mcBuf[i+2],mcBuf[i+3],mcBuf[i+4],mcBuf[i+5],mcBuf[i+6],mcBuf[i+7]);
			}
    } else {
			add_reply_message(request, "can not write PS packet to buffer");
			RDEBUG("can not write PS packet to buffer");
			break;
		}
		RDEBUG ("try connect to server %s:%s", SS7GW_SERVER, SS7GW_PORT);
		iSock = tcp_client_connect (SS7GW_SERVER, atol (SS7GW_PORT));
		if (-1 == iSock) {
      add_reply_message(request, "can not connect to SS7 gateway");
			RDEBUG("can not connect to SS7 gateway");
			break;
		}
		RDEBUG ("try send data to server %s:%s", SS7GW_SERVER, SS7GW_PORT);
		iFnRes = tcp_client_send (iSock, mcBuf, usPackLen);
		if (0 == iFnRes) {
      /* Ok */
    } else {
      add_reply_message(request, "can not send PS packet to SS7 gateway");
			RDEBUG("can not send PS packet to SS7 gateway");
			break;
		}
		RDEBUG ("try receive data from server %s:%s", SS7GW_SERVER, SS7GW_PORT);
		iFnRes = tcp_client_recv (iSock, mcBuf, sizeof(mcBuf));
		if (0 < iFnRes) {
      /* Ok */
			RDEBUG ("'%d' bytes received from SS7 gateway", iFnRes);
			int i;
			for (i = 0; i < iFnRes; i += 8) {
				RDEBUG ("PS packet dump: %02x%02x%02x%02x%02x%02x%02x%02x",
					mcBuf[i],mcBuf[i+1],mcBuf[i+2],mcBuf[i+3],mcBuf[i+4],mcBuf[i+5],mcBuf[i+6],mcBuf[i+7]);
			}
    } else {
      add_reply_message(request, "can not receive PS packet from SS7 gateway");
			RDEBUG("can not receive PS packet from SS7 gateway");
			break;
		}
		RDEBUG ("try to cleanup PS packet");
		pspack_cleanup (&soPSPackHolder);
		RDEBUG ("parse SS7 gateway response");
		iFnRes = pspack_parse_buf ((struct SPSRequest*)mcBuf, iFnRes, &soPSPackHolder);
		if (0 == iFnRes) {
      /* Ok */
    } else {
      add_reply_message(request, "ss7ge response parsing error");
			RDEBUG("ss7ge response parsing error");
			break;
		}
		RDEBUG ("analyze SS7 gateway response");
		struct SPSAttrList *psoAttrList = soPSPackHolder.m_psoAttrList;
		iFnRes = -1;

    mcReplyMessage[0] = '\0';

		while (psoAttrList) {
			switch (psoAttrList->m_soPackAttr.m_usAttrType) {
			case PS_RESULT:
        {
          memcpy (mcBuf, psoAttrList->m_pmucData, psoAttrList->m_soPackAttr.m_usAttrLen);
          mcBuf[psoAttrList->m_soPackAttr.m_usAttrLen] = '\0';
          iFnRes = snprintf(mcReplyMessage, sizeof(mcReplyMessage), "ss7gw response code: %s", mcBuf);
          if(0 < iFnRes) {
            if(sizeof(mcReplyMessage) > iFnRes) {
              /* Ok */
            } else {
              mcReplyMessage[sizeof(mcReplyMessage) - 1] = '\0';
            }
            RDEBUG (mcReplyMessage);
          }
          iFnRes = atoi(mcBuf);
        }
				break;
			case PS_DESCR:
				memcpy (mcBuf, psoAttrList->m_pmucData, psoAttrList->m_soPackAttr.m_usAttrLen);
				mcBuf[psoAttrList->m_soPackAttr.m_usAttrLen] = '\0';
        add_reply_message(request, mcBuf);
				RDEBUG ("ss7gw response description: %s", mcBuf);
				break;
			}
			psoAttrList = psoAttrList->m_psoNext;
		}
		if (0 == iFnRes) {
      /* Ok */ 
    } else {
      add_reply_message(request, mcReplyMessage);
			break;
		}
		RDEBUG("try receive triplets from ss7gw %s:%s", SS7GW_SERVER, SS7GW_PORT);
		iFnRes = tcp_client_recv (iSock, mcBuf, sizeof (mcBuf));
		if (0 < iFnRes) {
      /* Ok */
			RDEBUG ("'%d' bytes received from SS7 gateway", iFnRes);
			int i;
			for (i = 0; i < iFnRes; i += 8) {
				RDEBUG("PS packet dump: %02x%02x%02x%02x%02x%02x%02x%02x",
					mcBuf[i],mcBuf[i+1],mcBuf[i+2],mcBuf[i+3],mcBuf[i+4],mcBuf[i+5],mcBuf[i+6],mcBuf[i+7]);
			}
		} else {
      add_reply_message(request, "can not receive PS packet from SS7 gateway");
			RDEBUG ("can not receive PS packet from SS7 gateway");
			break;
		}
		RDEBUG ("try to cleanup PS packet");
		pspack_cleanup (&soPSPackHolder);
		RDEBUG ("parse SS7 gateway triplet request");
		iFnRes = pspack_parse_buf ((struct SPSRequest*)mcBuf, iFnRes, &soPSPackHolder);
		if (0 == iFnRes) {
      /* Ok */
    } else {
      add_reply_message(request, "analyze SS7 gateway triplets request parsing error");
			RDEBUG("analyze SS7 gateway triplets request parsing error");
			break;
		}
		RDEBUG ("analyze SS7 gateway triplet request");

		psoAttrList = soPSPackHolder.m_psoAttrList;
		mcDescr[0] = '\0';
    iFnRes = 0;

		while (psoAttrList) {
			vp = NULL;
			switch (psoAttrList->m_soPackAttr.m_usAttrType) {
			case PS_RESULT:
				memcpy (mcBuf, psoAttrList->m_pmucData, psoAttrList->m_soPackAttr.m_usAttrLen);
				mcBuf[psoAttrList->m_soPackAttr.m_usAttrLen] = '\0';
				iFnRes = atoi(mcBuf);
				RDEBUG("ss7gw result code: %s", mcBuf);
				break;
			case PS_DESCR:
				memcpy (mcBuf, psoAttrList->m_pmucData, psoAttrList->m_soPackAttr.m_usAttrLen);
				mcBuf[psoAttrList->m_soPackAttr.m_usAttrLen] = '\0';
				strncpy (mcDescr, mcBuf, sizeof (mcDescr) - 1);
				mcDescr[sizeof (mcDescr) - 1] = '\0';
        add_reply_message(request, mcDescr);
				RDEBUG ("ss7gw response description: %s", mcDescr);
				break;
			case SS7GW_IMSI:
				RDEBUG ("got 'SS7GW_IMSI' attribute");
				break;
			case RS_RAND1:
				RDEBUG ("got 'RS_RAND1' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_RAND1, PW_TYPE_OCTETS);
				break;
			case RS_SRES1:
				RDEBUG ("got 'RS_SRES1' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_SRES1, PW_TYPE_OCTETS);
				break;
			case RS_KC1:
				RDEBUG ("got 'RS_KC1' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_KC1, PW_TYPE_OCTETS);
				break;
			case RS_RAND2:
				RDEBUG ("got 'RS_RAND2' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_RAND2, PW_TYPE_OCTETS);
				break;
			case RS_SRES2:
				RDEBUG ("got 'RS_SRES2' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_SRES2, PW_TYPE_OCTETS);
				break;
			case RS_KC2:
				RDEBUG ("got 'RS_KC2' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_KC2, PW_TYPE_OCTETS);
				break;
			case RS_RAND3:
				RDEBUG ("got 'RS_RAND3' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_RAND3, PW_TYPE_OCTETS);
				break;
			case RS_SRES3:
				RDEBUG ("got 'RS_SRES3' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_SRES3, PW_TYPE_OCTETS);
				break;
			case RS_KC3:
				RDEBUG ("got 'RS_KC3' attribute");
				vp = paircreate (ATTRIBUTE_EAP_SIM_KC3, PW_TYPE_OCTETS);
				break;
			}
			if (vp) {
				memcpy (mcBuf, "0x", 2);
				memcpy (mcBuf + 2, psoAttrList->m_pmucData, psoAttrList->m_soPackAttr.m_usAttrLen);
				mcBuf[psoAttrList->m_soPackAttr.m_usAttrLen + 2] = '\0';
				RDEBUG ("try add '%s' value to rs-packet", mcBuf);
				vp = pairparsevalue (vp, mcBuf);
				pairadd (&request->reply->vps, vp);
			}
			psoAttrList = psoAttrList->m_psoNext;
		}
		if (iFnRes) {
      int iStrLen;

      mcReplyMessage[0] = '\0';
			if (0 == mcDescr[0]) {
				strcpy (mcDescr, "unknown ss7gw error");
			}
			iStrLen = snprintf (mcReplyMessage, sizeof(mcReplyMessage) - 1, "ss7gw triplets request error: code: %d; message: %s;", iFnRes, mcDescr);
      if(0 < iStrLen) {
        if(sizeof(mcReplyMessage) > iStrLen) {
          /* Ok */
        } else {
          mcReplyMessage[sizeof(mcReplyMessage) - 1] = '\0';
        }
        add_reply_message(request, mcReplyMessage);
        RDEBUG (mcReplyMessage);
      }
		}
	} while (0);

	if (-1 != iSock) {
		close (iSock);
	}
	RDEBUG ("try to cleanup PS packet");
	pspack_cleanup (&soPSPackHolder);

	/* test zone ***************************************************************/

	RDEBUG ("login attempt with IMSI \"%s\"", request->username->vp_strvalue);

	DEBUG("rlm_auc_drv: config");
	debug_pair_list(request->config_items);

	DEBUG("rlm_auc_drv: reply");
	debug_pair_list(request->reply->vps);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
