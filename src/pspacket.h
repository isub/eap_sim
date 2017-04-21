#include "CoACommon.h"

/* pspack_init initializes PS packet */
int pspack_init (struct SPSPackHolder *p_psoPSPackHolder, int p_iReqNumb, unsigned short m_usReqType);

/* pspack_set_reqnumb sets PS packet request number */
void pspack_set_reqnumb (struct SPSPackHolder *p_psoPSPackHolder, int p_iReqNumb);

/* pspack_set_reqtype set PS packet request type */
void pspack_set_reqtype (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usReqType);

/* pspack_set_reqtype set PS packet request type */
void pspack_set_packlen (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usPackLen);

/* pspack_add_attrtopack adds attribute to PS packet */
int pspack_add_attrtopack (struct SPSPackHolder *p_psoPSPackHolder, unsigned short p_usAttrType, unsigned short p_usDataLen, char *p_pmucData);

/* pspack_add_attrtolist adds attribute to attrlist */
int pspack_add_attrtolist (struct SPSAttrList **p_ppsoAttrList, unsigned short p_usAttrType, unsigned short p_usDataLen, char *p_pmucData);

/* pspack_fill_buf fills buffer whith PS packet content */
int pspack_fill_buf (struct SPSRequest *p_psoBuf, int p_iBufSize, struct SPSPackHolder *p_psoPSPackHolder);

/* pspack_parse_buf parses buffer */
int pspack_parse_buf (struct SPSRequest *p_psoBuf, int p_iDataLen, struct SPSPackHolder *p_psoPSPackHolder);

/* pspack_getattrlist retrives attribute list */
/* return value - count of attributes found */
/* p_usAttrType - requested attribute type. -1 - all of attribute types */
int pspack_getattrlist (struct SPSPackHolder *p_psoPSPackHolder, struct SPSAttrList **p_ppsoAttrList, unsigned short p_usAttrType);

/* pspack_cleanup_attrlist cleans SPSAttrList structure */
void pspack_cleanup_attrlist (struct SPSAttrList *p_psoAttrList);

/* pspack_cleanup cleans SPSPackHolder sturcture */
void pspack_cleanup (struct SPSPackHolder *p_psoPSPackHolder);
