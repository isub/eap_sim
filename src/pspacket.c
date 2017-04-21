#include "pspacket.h"

/* malloc */
#include <stdlib.h>
/* memset, memcpy */
#include <string.h>

/* htonl, htons */
#ifdef WIN32
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

int pspack_init (struct SPSPackHolder *p_psoPSPackHolder, int p_iReqNumb, unsigned short p_usReqType)
{
	int iRetVal = 0;

	do {
		/* check parameter */
		if (NULL == p_psoPSPackHolder) {
			iRetVal = -1;
			break;
		}

		/* clean up old data */
		pspack_cleanup (p_psoPSPackHolder);
		/* set request number */
		pspack_set_reqnumb (p_psoPSPackHolder, p_iReqNumb);
		/* set request type */
		pspack_set_reqtype (p_psoPSPackHolder, p_usReqType);
		/* set initial packet length */
		pspack_set_packlen (p_psoPSPackHolder, sizeof (p_psoPSPackHolder->m_soPackHdr));
	} while (0);

	return iRetVal;
}

void pspack_set_reqnumb (struct SPSPackHolder *p_psoPSPackHolder, int p_iReqNumb)
{
	do {
		/*check parameter */
		if (NULL == p_psoPSPackHolder) {
			break;
		}

		/* set PS packet request number */
		p_psoPSPackHolder->m_soPackHdr.m_uiReqNum = p_iReqNumb;
	} while (0);
}

void pspack_set_reqtype (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usReqType)
{
	do {
		/* check parameter */
		if (NULL == p_psoPSPackHolder) {
			break;
		}

		/* set PS packet request type */
		p_psoPSPackHolder->m_soPackHdr.m_usReqType = p_usReqType;
	} while (0);
}

void pspack_set_packlen (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usPackLen)
{
	do {
		if (NULL == p_psoPSPackHolder) {
			break;
		}

		/* set PS packet length */
		p_psoPSPackHolder->m_soPackHdr.m_usPackLen = p_usPackLen;
	} while (0);
}

int pspack_add_attrtopack (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usAttrType, unsigned short p_usDataLen, char *p_pmcData)
{
	int iRetVal = 0;
	int iFnRes;

	do {
		/* check parameters */
		if ((NULL == p_psoPSPackHolder) || (p_usDataLen && NULL == p_pmcData)) {
			iRetVal = -3;
			break;
		}

		iFnRes = pspack_add_attrtolist (&(p_psoPSPackHolder->m_psoAttrList), p_usAttrType, p_usDataLen, p_pmcData);
		if (iFnRes) {
			iRetVal = iFnRes;
			break;
		} else {
			p_psoPSPackHolder->m_soPackHdr.m_usPackLen += p_usDataLen + sizeof (struct SPSReqAttr);
		}
	} while (0);

	return iRetVal;
}

int pspack_add_attrtolist (struct SPSAttrList **p_ppsoAttrList, unsigned short p_usAttrType, unsigned short p_usDataLen, char *p_pmcData)
{
	int iRetVal = 0;
	struct SPSAttrList *psoTmp;

	do {
		/* check parameter */
		if (NULL == p_ppsoAttrList) {
			iRetVal = -15;
			break;
		}

		/* allocate memory for new attribute instance */
		psoTmp = (struct SPSAttrList*) malloc (sizeof (*psoTmp));
		if (NULL == psoTmp) {
			iRetVal = -16;
			break;
		}

		/* initilize attribute structure */
		memset (psoTmp, 0, sizeof (*psoTmp));
		/* set attribute type */
		psoTmp->m_soPackAttr.m_usAttrType = p_usAttrType;
		/* set attibute data length */
		psoTmp->m_soPackAttr.m_usAttrLen = p_usDataLen;
		/* copy attribute data */
		if (p_usDataLen) {
			/*allocate memory for attribute data */
			psoTmp->m_pmucData = (unsigned char*) malloc (p_usDataLen);
			if (NULL == psoTmp->m_pmucData) {
				iRetVal = -17;
				break;
			}
			/* copy attribute data */
			memcpy (psoTmp->m_pmucData, p_pmcData, p_usDataLen);
		}

		/* add attribute to tail of list */
		/* if attribute list is empty */
		if (NULL == *p_ppsoAttrList) {
			*p_ppsoAttrList = psoTmp;
		} else {
			/* look for last attribute */
			struct SPSAttrList *psoLast = *p_ppsoAttrList;
			while (psoLast->m_psoNext) {
				psoLast = psoLast->m_psoNext;
			}
			psoLast->m_psoNext = psoTmp;
		}

	} while (0);

	return iRetVal;
}

int pspack_fill_buf (struct SPSRequest *p_psoBuf, int p_iBufSize, struct SPSPackHolder *p_psoPSPackHolder)
{
	int iRetVal = 0;
	int iWriteInd;
	struct SPSAttrList *psoNext;
	struct SPSReqAttr *psoAttr;
	unsigned char *pucAttrData;

	do {
		/* check parameters */
		if (NULL == p_psoBuf && NULL == p_psoPSPackHolder) {
			iRetVal = -6;
			break;
		}

		/* check buffer size */
		if (p_iBufSize < p_psoPSPackHolder->m_soPackHdr.m_usPackLen) {
			/* not enough buffer space */
			iRetVal = -7;
			break;
		}

		/* fill PS packet request number */
		p_psoBuf->m_uiReqNum = htonl (p_psoPSPackHolder->m_soPackHdr.m_uiReqNum);
		/* fill PS packet request type */
		p_psoBuf->m_usReqType = htons (p_psoPSPackHolder->m_soPackHdr.m_usReqType);
		/* fill PS packet length */
		p_psoBuf->m_usPackLen = htons (p_psoPSPackHolder->m_soPackHdr.m_usPackLen);

		/* fill attribute list */
		iWriteInd = sizeof (*p_psoBuf);
		psoNext = p_psoPSPackHolder->m_psoAttrList;
		while (psoNext) {
			/* check buffer size in runtime */
			if (iWriteInd > p_iBufSize) {
				/* not enogh buffer space */
				iRetVal = -8;
				break;
			}
			/* determine place to write attribute fields */
			psoAttr = (struct SPSReqAttr*)(((unsigned char*)p_psoBuf) + iWriteInd);
			/* set attribute type */
			psoAttr->m_usAttrType = htons (psoNext->m_soPackAttr.m_usAttrType);
			/* set attribute length */
			psoAttr->m_usAttrLen = htons (psoNext->m_soPackAttr.m_usAttrLen + sizeof (psoNext->m_soPackAttr));
			if (psoNext->m_soPackAttr.m_usAttrLen) {
				/* check attribute data pointer */
				if (NULL == psoNext->m_pmucData) {
					iRetVal = -9;
					break;
				}
				pucAttrData = ((unsigned char*)psoAttr) + sizeof (psoNext->m_soPackAttr);
				/*copy attribute data */
				memcpy (pucAttrData, psoNext->m_pmucData, psoNext->m_soPackAttr.m_usAttrLen);
			}
			/* increase write index */
			iWriteInd += psoNext->m_soPackAttr.m_usAttrLen + sizeof (psoNext->m_soPackAttr);
			psoNext = psoNext->m_psoNext;
		}
		/* check for errors */
		if (iRetVal) {
			break;
		}
		/* compare predifined PS packet size with calculated PS packet size */
		/* must bo equal */
		if (iWriteInd != p_psoPSPackHolder->m_soPackHdr.m_usPackLen) {
			iRetVal = -10;
			break;
		}
	} while (0);

	return iRetVal;
}

int pspack_parse_buf (struct SPSRequest *p_psoBuf, int p_iDataLen, struct SPSPackHolder *p_psoPSPackHolder)
{
	int iRetVal = 0;
	int iReadInd;
	int iFnRes;
	struct SPSReqAttr *psoPackAttr;
	unsigned short usAttrType;
	unsigned short usDataLen;
	unsigned char *pmucData;

	do {
		/* check parameters */
		if (NULL == p_psoBuf || p_iDataLen < sizeof (*p_psoBuf) || NULL == p_psoPSPackHolder) {
			iRetVal = -11;
			break;
		}

		/* set request number */
		p_psoPSPackHolder->m_soPackHdr.m_uiReqNum = htonl (p_psoBuf->m_uiReqNum);
		/* set request type */
		p_psoPSPackHolder->m_soPackHdr.m_usReqType = htons (p_psoBuf->m_usReqType);
		/* set packet length */
		p_psoPSPackHolder->m_soPackHdr.m_usPackLen = htons (p_psoBuf->m_usPackLen);

		/* check data len */
		if (p_iDataLen < p_psoPSPackHolder->m_soPackHdr.m_usPackLen) {
			iRetVal = -12;
			break;
		}

		/* parse attribute list */
		iReadInd = sizeof (*p_psoBuf);
		while (iReadInd < p_iDataLen && iReadInd < p_psoPSPackHolder->m_soPackHdr.m_usPackLen) {
			/* determine attribute pointer */
			psoPackAttr = (struct SPSReqAttr*)((unsigned char*)p_psoBuf + iReadInd);
			/* get attr type */
			usAttrType = ntohs (psoPackAttr->m_usAttrType);
			usDataLen = ntohs (psoPackAttr->m_usAttrLen) - sizeof (*psoPackAttr);
			if (usDataLen) {
				pmucData = (unsigned char*)psoPackAttr + sizeof (*psoPackAttr);
			} else {
				pmucData = NULL;
			}
			/* add attribute to packet holder */
			iFnRes = pspack_add_attrtolist (&(p_psoPSPackHolder->m_psoAttrList), usAttrType, usDataLen, pmucData);
			if (iFnRes) {
				iRetVal = iFnRes;
				break;
			}
			/* increase read index */
			iReadInd += usDataLen + sizeof (*psoPackAttr);
		}
		/* check for errors */
		if (iRetVal) {
			break;
		}
		/* compare defined packet size with calculated packet size */
		/* must be equal */
		if (iReadInd != p_psoPSPackHolder->m_soPackHdr.m_usPackLen) {
			iRetVal = -13;
			break;
		}
	} while (0);

	return iRetVal;
}

int pspack_getattrlist (struct SPSPackHolder *p_psoPSPackHolder, struct SPSAttrList **p_ppsoAttrList, unsigned short p_usAttrType)
{
	int iRetVal = 0;
	int iFnRes;
	unsigned short usAttrType;
	unsigned short usAttrLen;
	unsigned char *pmucAttrData;
	struct SPSAttrList *psoTmp;

	do {
		/* check parameter */
		if (NULL == p_psoPSPackHolder || NULL == p_ppsoAttrList) {
			iRetVal = -14;
			break;
		}

		psoTmp = p_psoPSPackHolder->m_psoAttrList;
		while (psoTmp) {
			if (p_usAttrType == (unsigned short) -1 || p_usAttrType == psoTmp->m_soPackAttr.m_usAttrType) {
				usAttrType = psoTmp->m_soPackAttr.m_usAttrType;
				usAttrLen = psoTmp->m_soPackAttr.m_usAttrLen;
				pmucAttrData = psoTmp->m_pmucData;
				iFnRes = pspack_add_attrtolist (p_ppsoAttrList, usAttrType, usAttrLen, pmucAttrData);
				if (iFnRes) {
					iRetVal = iFnRes;
					break;
				}
			}
			psoTmp = psoTmp->m_psoNext;
		}
	} while (0);

	return iRetVal;
}

void pspack_cleanup_attrlist (struct SPSAttrList *p_psoAttrList)
{
	struct SPSAttrList *psoTmp;
	struct SPSAttrList *psoNext;

	do {
		/* check parameter */
		if (NULL == p_psoAttrList) {
			break;
		}
		psoTmp = NULL;
		psoNext = p_psoAttrList;

		while (psoNext) {
			psoTmp = psoNext->m_psoNext;
			if (psoNext->m_pmucData) {
				free (psoNext->m_pmucData);
			}
			free (psoNext);
			psoNext = psoTmp;
		}
	} while (0);
}

void pspack_cleanup (struct SPSPackHolder *p_psoPSPackHolder)
{
	do {
		/* check parameter */
		if (NULL == p_psoPSPackHolder) {
			break;
		}

		/* clean attribute list */
		pspack_cleanup_attrlist (p_psoPSPackHolder->m_psoAttrList);

		memset (p_psoPSPackHolder, 0, sizeof (*p_psoPSPackHolder));
	} while (0);
}
