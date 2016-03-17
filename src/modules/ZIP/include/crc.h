/*
**  CRC.H - header file for SNIPPETS CRC and checksum functions
*/

#ifndef CRC__H
#define CRC__H

#include <stdlib.h>           /* For size_t                 */
#include <iostream>
#include <cstdint>
/*
**  File: ARCCRC16.C
*/
typedef enum {Error_ = -1, Success_, False_ = 0, True_} Boolean_T;
void init_crc_table(void);
uint16_t crc_calc(uint16_t crc, char *buf, unsigned nbytes);
void do_file(char *fn);

/*
**  File: CRC_32.C
*/

#define UPDC32(octet,crc) (crc_32_tab[((crc)\
     ^ ((uint8_t)octet)) & 0xff] ^ ((crc) >> 8))

uint32_t updateCRC32(unsigned char ch, uint32_t crc);
Boolean_T crc32file(char *name, uint32_t *crc, long *charcnt);
uint32_t crc32buf(char *buf, size_t len);




#endif /* CRC__H */
