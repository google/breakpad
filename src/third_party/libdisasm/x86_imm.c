#include "qword.h"
#include "x86_imm.h"

#include <stdio.h>
#include <string.h>

unsigned int x86_imm_signsized( unsigned char * buf, size_t buf_len,
				void *dest, unsigned int size ) {
	if ( size > buf_len ) {
		return 0;
	}

	memcpy(dest, buf, size);
	return (size);
}

unsigned int x86_imm_sized( unsigned char * buf, size_t buf_len, void *dest,
			    unsigned int size ) {
	unsigned char *cp = (unsigned char *) dest;
	unsigned short *sp = (unsigned short *) dest;
	uint32_t *lp = (uint32_t *) dest;
	qword_t *qp = (qword_t *) dest;

	if ( size > buf_len ) {
		return 0;
	}

	/* Copy 'size' bytes from *buf to *op
	 * return number of bytes copied */
	switch (size) {
		case 1:		/* BYTE */
			*cp =  *((unsigned char *) buf);
			break;
		case 2:		/* WORD */
			*sp =  *((unsigned short *) buf);
			break;
		case 6:
		case 8:		/* QWORD */
			*qp = *((qword_t *) buf);
			break;
		case 4:		/* DWORD */
		default:
			*lp = *((uint32_t *) buf);
			break;
	}

	return (size);
}

