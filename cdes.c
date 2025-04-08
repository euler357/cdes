/**************************************************************
*
*  Chris's Mini-DES Encryption Program
*
*  Author:  Chris K Cockrum
*
*  Notes:   Assumes 32 bit word size and Little Endian
*           Byte addressable machine
*
**************************************************************/

#include <stdio.h>
#include <stdlib.h>

/* Number of Rounds to Perform */
#define NUMROUNDS 16

/* Expansion Matrix */
char e[24]={   15,  0,  1,  2,  3,  4,
               3 ,  4,  5,  6,  7,  8,
               7 ,  8,  9, 10, 11, 12,
               11, 12, 13, 14, 15,  1   };

/* S-Boxes */
char s[4][4][16]={
         { {4,14,3,1,2,15,11,8,13,10,6,12,5,9,0,7},
           {10,15,7,4,14,2,13,1,0,6,12,11,9,5,3,8},
           {1,2,4,8,13,6,14,11,15,12,9,7,3,10,5,0},
           {1,12,8,2,4,9,5,7,15,11,3,14,10,0,6,13}, },
         { {1,15,8,14,6,11,3,4,9,2,7,13,12,0,5,10},
           {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
           {0,14,7,11,1,10,4,13,5,8,12,6,9,3,2,15},
           {14,8,10,1,3,15,4,2,11,6,7,12,0,5,13,9} },
         { {0,10,9,14,6,3,15,5,1,12,13,7,11,4,2,8},
           {11,7,0,9,3,4,6,10,2,8,5,14,12,13,15,1},
           {1,4,5,15,3,0,11,13,2,6,12,9,10,14,8,7},
           {13,10,1,0,6,9,8,7,4,15,14,3,11,5,2,12} },
         { {11,12,1,3,0,6,9,10,14,8,2,5,3,13,4,15},
           {1,8,11,5,6,15,0,3,4,7,2,12,13,10,14,9},
           {1,3,6,9,0,12,11,7,13,15,10,14,5,2,8,4},
           {13,15,0,6,1,3,8,9,4,5,10,11,12,7,2,14} }
         };

/* f function fixed permutation */
char p[16]= {  10, 9, 5, 14,
               12, 2, 4, 0,
               3,  1, 6, 15,
               13, 8, 7, 11 };

/* Key Schedule initial Permutation */
char pc1[32]= {
               21,26,1,23,  13,3,14,15,
               22,31,0,7,  19,29,11,4,
               9,17,10,12, 30,25,24,8,
               16,6,18,5,  20,2,27,28
               };

/* Key schedule pc2 permutation */
char pc2[24]= {
               31,1,6,12,  28,10,3,9,
               13,7,19,22, 29,15,30,11,
               0,17,2,27,  20,26,21,14
               };

/* Initialize keytable */
unsigned int keytable[16]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 } ;


/**************************************************************
*
*  Name:       expansion
*
*  Function:   Perform 16 to 24 bit expansion
*
**************************************************************/
unsigned int expansion(unsigned int indata)
{
   unsigned int outdata=0; /* output data */
   unsigned int n;         /* loop variable */

   /* Permute / Expand to 24 bits */
   for (n=0;n<24;n++)
      outdata=outdata | ( (indata>>e[n]) & 0x1) << n;

   return outdata;
}

/**************************************************************
*
*  Name:       sbox
*
*  Function:   Perform sbox non-linear mapping
*
**************************************************************/
unsigned int sbox(unsigned int indata)
{
   unsigned int outdata=0;    /* output data */
   unsigned int n;            /* loop variable */
   unsigned int b0,b1,b2,b3;  /* 6 Bit data */
   unsigned int c0,c1,c2,c3;  /* 4 Bit data */

   /* Extract 6 bit values from input */
   b0=(indata>>18) & 0x3f;
   b1=(indata>>12) & 0x3f;
   b2=(indata>>6)  & 0x3f;
   b3= indata      & 0x3f;

   /* Calculate 4 bit values from input and s-boxes */
   c0=s[0][(b0>>4) & 0x3][b0 & 0xf];
   c1=s[1][(b1>>4) & 0x3][b1 & 0xf];
   c2=s[2][(b2>>4) & 0x3][b2 & 0xf];
   c3=s[3][(b3>>4) & 0x3][b3 & 0xf];

   /* Concatenate 4 bit values to output */
   outdata=(c0<<12) | (c1<<8) | (c2<<4) | c3;

   return outdata;
}

/**************************************************************
*
*  Name:       p_function
*
*  Function:   Perform fixed permutation for f function
*
**************************************************************/
unsigned int p_function(unsigned int indata)
{
   unsigned int outdata=0; /* Output Data */
   unsigned int n;

   /* Do permutation */
   for (n=0;n<16;n++)
      outdata= (outdata | (((indata>>p[n])&1)<<n));

   return outdata;
}


/**************************************************************
*
*  Name:       sched_keys
*
*  Function:   Calculate Key Schedule
*
**************************************************************/
unsigned int sched_keys(unsigned int keyseed, unsigned int *key)
{
   unsigned int   keyc,       /* Left temp key */
                  shift=0,    /* Shift of key */
                  keyd,       /* Right temp key */
                  keytemp=0;  /* Temp Key */
   unsigned int   n,          /* Loop variable */
                  i;          /* Loop variable */

   /* Do PC1 permutation */
   for (n=0;n<32;n++)
      keytemp|=(((keyseed>>pc1[n])&1)<<n);

   /* Split permuted key in half and duplicate */
   keyc = ((keytemp>>16)&0xffff)+(((keytemp>>16)&0xffff)<<16);
   keyd = (keytemp&0xffff)+((keytemp&0xffff)<<16);

   /* Calculate keys */
   for (n=0;n<NUMROUNDS;n++) {

      /* Calculate Shift Values */
      if ((n%3)==0)
         shift+=2;
      else
         shift++;

      shift=shift%NUMROUNDS;

      /* Construct keytemp from shifted halves */
      keytemp=(((keyc>>shift)&0xffff)<<16)+((keyd>>shift)&0xffff);

      /* Make sure key[n] is cleared before or'ing */
      key[n]=0;

      /* Do PC2 permutation */
      for (i=0;i<24;i++)
         key[n]|=( ( (keytemp >> pc2[i]) & 1) << i );

   #ifdef DEBUG
      printf("key[%d]\t=\t%X\n",n,key[n]);
   #endif

      }
   return 0;
}

/**************************************************************
*
*  Name:       f_function
*
*  Function:   Performs DES f function
*
**************************************************************/
unsigned int f_function(unsigned int indata,unsigned int key)
{
   unsigned int outdata=0; /* Output Data */

   /* Expand indata */
   outdata = expansion(indata);

   /* Xor data with key */
   outdata = outdata ^ key;

   /* Perform s-box permutations */
   outdata = sbox(outdata);

   /* Perform fixed permutation */
   outdata = p_function(indata);
   
   return outdata;
   
}


/**************************************************************
*
*  Name:       cdes
*
*  Function:   Performs encryption / descryption
*
**************************************************************/
unsigned int cdes(unsigned int indata,unsigned int *key,int mode)
{
   unsigned int   outdata,    /* output word */
                  lin,        /* left input temp */
                  lout,       /* left output temp */
                  rin,        /* right input temp */
                  rout,       /* right output temp */
                  n;          /* loop variable */

   #ifdef DEBUG
      printf("In: %X\t",indata);
   #endif

   /* Loop until number of rounds */
   for (n=0;n<NUMROUNDS;n++) {

      /* Get left and right from indata */
      lin = (indata >> 16) & 0xffff;
      rin = indata & 0xffff;

      /* Encrypt */
      if (mode>0){
         lout = rin;
         rout = lin ^ (f_function(rin,key[n]));
         }

      /* Decrypt */
      else  {
         rout = lin;
         lout = rin ^ (f_function(lin,key[NUMROUNDS-n]));
         }
	
      /* Assign left and right to outdata */
      outdata=((lout&0xffff)<<16) | (rout&0xffff);
      indata=outdata;
      }

   #ifdef DEBUG
      printf("Out: %X\n",outdata);
   #endif

   return outdata;
}


/**************************************************************
*
*  Name:       main
*
*  Function:   Main function
*
**************************************************************/
int main(int argc, char **argv)
{
   FILE *infile;           /* Input File */
   FILE *outfile;          /* Output File */
   FILE *keyfile;          /* Key file */
   int mode=0;             /* Mode: 1=encrypt , -1=decrypt */
   char tempstring[40];    /* Temp String for getting input filenames */
   unsigned int indata;    /* Input Word */
   unsigned int outdata;   /* Output Word */
   unsigned int temp;      /* Temp variable */
   unsigned int n;         /* Loop variable */
   unsigned int keyseed;   /* Original Key */
   int ret;                /* Return value for functions */

	/* Print Title */
   printf("\nChris's Mini-DES\n");

	/* Check input Parameters or prompt for them */
   if (argc>=2)
      if (**++argv=='e') {
         mode=1;
         printf("Encrypt Mode\n");
         }
      else if (**argv=='d') {
         mode=-1;
         printf("Decrypt Mode\n");
         }
      else {
         printf("Usage: cdes mode infile outfile keyfile\n");
         printf("or just: cdes\n");
         return 1;
         }
   else {
         printf("Enter Mode (e/d):");
         if (getc(stdin)=='e') {
            mode=1;
            printf("Encrypt Mode\n");
            }
         else {
            mode=-1;
            printf("Decrypt Mode\n");
            }
      }
   if (argc>=3) {
      if((infile=fopen(*++argv,"rb"))==NULL) {
         printf("Error Opening Input File!!!\n");
         return 1;
         }
      printf("Input File:  %s\n",*argv);
      }
   else {
      printf("Enter Input Filename: ");
      ret=scanf("%s",&tempstring[0]);
      if((infile=fopen(tempstring,"rb"))==NULL) {
         printf("Error Opening Input File!!!\n");
         return 1;
         }
      }
   if (argc>=4) {
      if((outfile=fopen(*++argv,"wb"))==NULL) {
         printf("Error Opening Output File!!!\n");
         fclose(infile);
         return 1;
         }
      printf("Output File: %s\n",*argv);
      }
   else {
      printf("Enter Output Filename: ");
      ret=scanf("%s",&tempstring[0]);
      if((outfile=fopen(tempstring,"wb"))==NULL) {
         printf("Error Opening Output File!!!\n");
         return 1;
         }
      }
   if (argc>=5) {
      if((keyfile=fopen(*++argv,"r"))==NULL) {
         printf("Error Opening Key File!!!\n");
         fclose(infile);
         fclose(outfile);
         }
      printf("Key File:    %s\n",*argv);
      }
   else {
      printf("Enter Key Filename: ");
      ret=scanf("%s",&tempstring[0]);
      if((keyfile=fopen(tempstring,"r"))==NULL) {
         printf("Error Opening Key File!!!\n");
         return 1;
         }
      }

   /* Get key from file */
   if(fscanf(keyfile,"%x",&keyseed)==0)
	{
        printf("Error Reading Key File!!!\n");
        return 1;
    }

   /* Compute key schedule */
   sched_keys(keyseed,keytable);

   /* Add LF */
   printf("\n");

   /* Get Input Word */
   while (fread(&indata,1,4,infile)) {

   /* Perform encryption / decryption */
      outdata=cdes(indata,keytable,mode);

   /* Clear Input Variable */
      indata=0;

   /* Write Output Word */
      fwrite(&outdata,4,1,outfile);
      }

   /* Close open files */
   fclose(infile);
   fclose(outfile);
   fclose(keyfile);
}
