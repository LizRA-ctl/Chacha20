/* Octuber 18, 2020
   Lizbeth Ruz Armas
   This program implement the Chacha cipher using 32 bit words and
   20 quarter rounds */

	#include <string.h>
	#include <stdio.h>
        #include <stdint.h>
        #include <unistd.h>
        #include <fcntl.h>
        #include <inttypes.h>

	//Routing to get random numbers
        int randomnum (void){

        uint32_t  buffer[32];
        unsigned long urandom;
        uint32_t myrand[1];

        urandom = open("/dev/urandom", O_RDONLY);
        read(urandom, buffer,32);
        //buffer contains the random data
        close(urandom);
        myrand[0]=buffer[0];

        return *myrand;
       }

        //Defining quarter-rounds equations for salsa algorithm
        #define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        #define QR(a, b, c, d)( \
        a += b,  d ^= a,  d = ROTL(d,16),	\
        c += d,  b ^= c,  b = ROTL(b,12),	\
        a += b,  d ^= a,  d = ROTL(d, 8),	\
        c += d,  b ^= c,  b = ROTL(b, 7))

        #define ROUNDS 20

        //convert 32 bits to 8 using little endian format
        #define U32_TO_8LITTLE(a, b) \
                { (a)[0] = (b >>  0) & 0xff; (a)[1] = (b >>  8) & 0xff; \
                  (a)[2] = (b >> 16) & 0xff; (a)[3] = (b >> 24) & 0xff; }
	//convert 8 bits to 32 using little endian format
	#define U8_TO_32LITTLE(a)   \
        (((uint32_t)((a)[0])      ) | ((uint32_t)((a)[1]) <<  8) | \
	((uint32_t)((a)[2]) << 16) | ((uint32_t)((a)[3]) << 24))

        //ChaCha quarter-round functions, defining 20 rounds ---> ChaCha20

        uint32_t chacha20_funct(unsigned char out[64], const uint32_t in[16]) {

        int i;
        uint32_t x[16];
        for(i = 0; i < 16; ++i){
            x[i] = in[i];
        //printf("Entrada   %u \n\r", in[i]);
                               }
        //10loops × 2rounds/loop = 20 rounds
        for(i =ROUNDS; i >0 ; i -= 2) {
	// Odd round
	QR(x[0], x[4], x[ 8], x[12]); // column 0
	QR(x[1], x[5], x[ 9], x[13]); // column 1
	QR(x[2], x[6], x[10], x[14]); // column 2
	QR(x[3], x[7], x[11], x[15]); // column 3
	// Even round
	QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
	QR(x[1], x[6], x[11], x[12]); // diagonal 2
	QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
	QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
				      }
	for (i = 0; i < 16; ++i)
	x[i] = x[i] + in[i];

	for (i = 0; i < 16; ++i) {
	    U32_TO_8LITTLE(out + 4 * i, x[i]);
   				 }
//	printf("\n\r\r----------------------------\n\r");

   return 0;

}
	void chacha20_core(unsigned char *out, const unsigned char *in, unsigned int inLen,
		 const unsigned char key[32], const unsigned char nonce[8],
		 uint64_t counter, const unsigned char constant[16]) {

    unsigned char block[64];
    uint32_t input[16];
    unsigned int i;

    //Asigning all the initial state (4x4 block) of Salsa
    //Converting the block inputs from 8b to 32 using little endian format

    input[0] = U8_TO_32LITTLE(constant + 0);
    input[1] = U8_TO_32LITTLE(constant + 4);
    input[2] = U8_TO_32LITTLE(constant + 8);
    input[3] = U8_TO_32LITTLE(constant + 12);

    input[4]  = U8_TO_32LITTLE(key + 0);
    input[5]  = U8_TO_32LITTLE(key + 4);
    input[6]  = U8_TO_32LITTLE(key + 8);
    input[7]  = U8_TO_32LITTLE(key + 12);
    input[8]  = U8_TO_32LITTLE(key + 16);
    input[9]  = U8_TO_32LITTLE(key + 20);
    input[10] = U8_TO_32LITTLE(key + 24);
    input[11] = U8_TO_32LITTLE(key + 28);

    input[12] = counter;
    input[13] = counter >> 32;

    input[14] = U8_TO_32LITTLE(nonce + 0);
    input[15] = U8_TO_32LITTLE(nonce + 4);

    //XORing the plaint text with the Salsa function routine

    while (inLen >= 32) {
	chacha20_funct(block, input);
	for (i = 0; i < 32; i++) {
	    out[i] = in[i] ^ block[i];
				}
	//increasing the counters
	input[12]++;
	if (input[12] == 0) {
	    input[13]++;
	}
	inLen -= 32;
	in += 32;
	out += 32;
}
    if (inLen > 0) {
	chacha20_funct(block, input);
	for (i = 0; i < inLen; i++){
	    out[i] = in[i] ^ block[i];
	printf("Chacha output %d \n\r", out[i]);
	}
 	printf("\n\r-----------------------\n\r");

    }
}

//-----------------------------------------------------------------

     int main ()
	{
       const unsigned char plaintx[]={ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
       unsigned int inlen=strlen(plaintx);
       unsigned char out[32];
       int i;
       unsigned char key[32];
       unsigned char nonce[8];
       unsigned char outA[16];
       uint64_t counter;

       //Getting the variables of the starting block

       //Assigning Ci (x1-x3)
       static const unsigned char constant[16] = "expand 32-byte k";

       //Assigning key (x4-x11)
       for (i=0; i<32; i++) // {
       key[i]= randomnum();
       //printf("key %u \n", key[i]);}

       //Getting  n0-n1 (x[14]-x[15])
       for (i=0; i<8; i++)
       nonce[8]= randomnum();
       //Getting   (x[12]-x[13])
       counter=0;
       //running salsa20
       printf("\n\rRunning Chacha20 ******* \n\r");
       chacha20_core(out, plaintx,inlen,key, nonce,counter,constant);

       //getting the original message
       printf("\n\rRunnig Chacha20 again, getting the original text ****** \n\r");
       chacha20_core(outA,out,inlen,key, nonce,counter,constant);

       return 0;

 }

