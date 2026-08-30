<?php

namespace PPOLib\Algo;

use PPOLib\Util;

/**
* портировано с  https://github.com/storojs72/bc-dstu-csharp
* шифрование  согласно ДСТУ 7524  (Калина)
*/


class DSTU7624
{
 
     const  BITS_IN_WORD = 64;
     const  BITS_IN_BYTE = 8;

     /* Block words size. */
     const  kNB_128 = 2;
     const  kNB_256 = 4;
     const  kNB_512 = 8;

     /* Key words size. */
     const  kNK_128 = 2;
     const  kNK_256 = 4;
     const  kNK_512 = 8;

     /* Block bits size. */
     const  kBLOCK_128 = 128;
     const  kBLOCK_256 = 256;
     const  kBLOCK_512 = 512;

     /* Block bits size. */
     const  kKEY_128 = 128;
     const  kKEY_256 = 256;
     const  kKEY_512 = 512;

     /* Number of enciphering rounds size depending on key length. */
     const  kNR_128 = 10;
     const  kNR_256 = 14;
     const  kNR_512 = 18;

     const  REDUCTION_POLYNOMIAL = 0x011d;  /* x^8 + x^4 + x^3 + x^2 + 1 */


     private  $nb;  /* Number of 64-bit words in enciphering block. */
     private  $nk;  /*< Number of 64-bit words in key. */
     private  $roundKeysAmount;  /*< Number of enciphering rounds. */

     private   $internalState = [];  
     private $bufOff=0;
     private $buf=[];

     private   $workingKey = null;
     private   $roundKeys = null;  /*< Round key computed from enciphering key. */


     private   $blockSizeBits;
     private   $keySizeBits;

     private   $forEncryption;
     private   $sboxesForEncryption=[];
     private   $sboxesForDecryption=[];
     private   $mdsMatrix=[];
     private   $mdsInvMatrix=[];
     
 
   public function __construct($blockSizeBits=256, $keySizeBit=256) {
       $this->blockSizeBits = $blockSizeBits;
       $this->keySizeBits = $keySizeBit;
     
       if ($this->blockSizeBits == self::kBLOCK_128)
       {
            $this->nb = self::kBLOCK_128 / self::BITS_IN_WORD;
            if ($this->keySizeBits == self::kKEY_128)
            {
                 $this->nk = self::kKEY_128 / self::BITS_IN_WORD;
                 $this->roundKeysAmount = self::kNR_128;
            }
            else if ($this->keySizeBits == self::kKEY_256)
            {
                 $this->nk = self::kKEY_256 / self::BITS_IN_WORD;
                 $this->roundKeysAmount = self::kNR_256;
            }
            else
            {
                 throw new \Exception("Unsupported key size");
            }
       }
       else if ($this->blockSizeBits == 256)
       {
            $this->nb = self::kBLOCK_256 / self::BITS_IN_WORD;
            if ($this->keySizeBits == self::kKEY_256)
            {
                 $this->nk = self::kKEY_256 / self::BITS_IN_WORD;
                 $this->roundKeysAmount = self::kNR_256;
            }
            else if ($this->keySizeBits == self::kKEY_512)
            {
                 $this->nk = self::kKEY_512 / self::BITS_IN_WORD;
                 $this->roundKeysAmount = self::kNR_512;
            }
            else
            {
                 throw new \Exception("Unsupported key size");
            }
       }
       else if ($this->blockSizeBits == self::kBLOCK_512)
       {
            $this->nb = self::kBLOCK_512 / self::BITS_IN_WORD;
            if ($this->keySizeBits == self::kKEY_512)
            {
                 $this->nk = self::kKEY_512 / self::BITS_IN_WORD;
                 $this->roundKeysAmount = self::kNR_512;
            }
            else
            {
                 throw new \Exception("Unsupported key size");
            }
       }
       else
       {
            throw new \Exception("Unsupported block size");
       }

       $this->internalState = Util::alloc($this->nb)  ;

        
       //workingKey = new ulong[nk];

       for ( $i = 0; $i < $this->roundKeysAmount + 1; $i++)
       {
            $this->roundKeys[$i] = Util::alloc($this->nb) ;
       }   
       
       
       $this->sboxesForEncryption[0]=[  
                    0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09, 
                    0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39, 
                    0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6, 
                    0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1, 
                    0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27, 
                    0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41, 
                    0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e, 
                    0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55, 
                    0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff, 
                    0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1, 
                    0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76, 
                    0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26, 
                    0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82, 
                    0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8, 
                    0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d, 
                    0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80 ];

       $this->sboxesForEncryption[1]=[  
                  0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8, 
                  0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d, 
                  0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d, 
                  0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc, 
                  0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee, 
                  0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca, 
                  0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20, 
                  0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f, 
                  0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51, 
                  0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98, 
                  0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9, 
                  0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05, 
                  0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82, 
                  0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad, 
                  0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59, 
                  0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7  ];
 
       $this->sboxesForEncryption[2]=[     
            0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59, 
            0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1, 
            0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72, 
            0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90, 
            0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35, 
            0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48, 
            0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38, 
            0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33, 
            0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29, 
            0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83, 
            0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2, 
            0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43, 
            0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82, 
            0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91, 
            0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44, 
            0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67 ];
 
       $this->sboxesForEncryption[3]=[              
                    0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f, 
                    0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd, 
                    0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66, 
                    0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf, 
                    0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99, 
                    0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71, 
                    0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60, 
                    0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b, 
                    0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09, 
                    0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2, 
                    0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7, 
                    0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a, 
                    0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39, 
                    0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef, 
                    0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36, 
                    0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61  ];
       
       
       
       $this->sboxesForDecryption[0]=[
           0xa4, 0xa2, 0xa9, 0xc5, 0x4e, 0xc9, 0x03, 0xd9, 0x7e, 0x0f, 0xd2, 0xad, 0xe7, 0xd3, 0x27, 0x5b, 
           0xe3, 0xa1, 0xe8, 0xe6, 0x7c, 0x2a, 0x55, 0x0c, 0x86, 0x39, 0xd7, 0x8d, 0xb8, 0x12, 0x6f, 0x28, 
           0xcd, 0x8a, 0x70, 0x56, 0x72, 0xf9, 0xbf, 0x4f, 0x73, 0xe9, 0xf7, 0x57, 0x16, 0xac, 0x50, 0xc0, 
           0x9d, 0xb7, 0x47, 0x71, 0x60, 0xc4, 0x74, 0x43, 0x6c, 0x1f, 0x93, 0x77, 0xdc, 0xce, 0x20, 0x8c, 
           0x99, 0x5f, 0x44, 0x01, 0xf5, 0x1e, 0x87, 0x5e, 0x61, 0x2c, 0x4b, 0x1d, 0x81, 0x15, 0xf4, 0x23, 
           0xd6, 0xea, 0xe1, 0x67, 0xf1, 0x7f, 0xfe, 0xda, 0x3c, 0x07, 0x53, 0x6a, 0x84, 0x9c, 0xcb, 0x02, 
           0x83, 0x33, 0xdd, 0x35, 0xe2, 0x59, 0x5a, 0x98, 0xa5, 0x92, 0x64, 0x04, 0x06, 0x10, 0x4d, 0x1c, 
           0x97, 0x08, 0x31, 0xee, 0xab, 0x05, 0xaf, 0x79, 0xa0, 0x18, 0x46, 0x6d, 0xfc, 0x89, 0xd4, 0xc7, 
           0xff, 0xf0, 0xcf, 0x42, 0x91, 0xf8, 0x68, 0x0a, 0x65, 0x8e, 0xb6, 0xfd, 0xc3, 0xef, 0x78, 0x4c, 
           0xcc, 0x9e, 0x30, 0x2e, 0xbc, 0x0b, 0x54, 0x1a, 0xa6, 0xbb, 0x26, 0x80, 0x48, 0x94, 0x32, 0x7d, 
           0xa7, 0x3f, 0xae, 0x22, 0x3d, 0x66, 0xaa, 0xf6, 0x00, 0x5d, 0xbd, 0x4a, 0xe0, 0x3b, 0xb4, 0x17, 
           0x8b, 0x9f, 0x76, 0xb0, 0x24, 0x9a, 0x25, 0x63, 0xdb, 0xeb, 0x7a, 0x3e, 0x5c, 0xb3, 0xb1, 0x29, 
           0xf2, 0xca, 0x58, 0x6e, 0xd8, 0xa8, 0x2f, 0x75, 0xdf, 0x14, 0xfb, 0x13, 0x49, 0x88, 0xb2, 0xec, 
           0xe4, 0x34, 0x2d, 0x96, 0xc6, 0x3a, 0xed, 0x95, 0x0e, 0xe5, 0x85, 0x6b, 0x40, 0x21, 0x9b, 0x09, 
           0x19, 0x2b, 0x52, 0xde, 0x45, 0xa3, 0xfa, 0x51, 0xc2, 0xb5, 0xd1, 0x90, 0xb9, 0xf3, 0x37, 0xc1, 
           0x0d, 0xba, 0x41, 0x11, 0x38, 0x7b, 0xbe, 0xd0, 0xd5, 0x69, 0x36, 0xc8, 0x62, 0x1b, 0x82, 0x8f];    
       
       $this->sboxesForDecryption[1]=[
            0x83, 0xf2, 0x2a, 0xeb, 0xe9, 0xbf, 0x7b, 0x9c, 0x34, 0x96, 0x8d, 0x98, 0xb9, 0x69, 0x8c, 0x29, 
            0x3d, 0x88, 0x68, 0x06, 0x39, 0x11, 0x4c, 0x0e, 0xa0, 0x56, 0x40, 0x92, 0x15, 0xbc, 0xb3, 0xdc, 
            0x6f, 0xf8, 0x26, 0xba, 0xbe, 0xbd, 0x31, 0xfb, 0xc3, 0xfe, 0x80, 0x61, 0xe1, 0x7a, 0x32, 0xd2, 
            0x70, 0x20, 0xa1, 0x45, 0xec, 0xd9, 0x1a, 0x5d, 0xb4, 0xd8, 0x09, 0xa5, 0x55, 0x8e, 0x37, 0x76, 
            0xa9, 0x67, 0x10, 0x17, 0x36, 0x65, 0xb1, 0x95, 0x62, 0x59, 0x74, 0xa3, 0x50, 0x2f, 0x4b, 0xc8, 
            0xd0, 0x8f, 0xcd, 0xd4, 0x3c, 0x86, 0x12, 0x1d, 0x23, 0xef, 0xf4, 0x53, 0x19, 0x35, 0xe6, 0x7f, 
            0x5e, 0xd6, 0x79, 0x51, 0x22, 0x14, 0xf7, 0x1e, 0x4a, 0x42, 0x9b, 0x41, 0x73, 0x2d, 0xc1, 0x5c, 
            0xa6, 0xa2, 0xe0, 0x2e, 0xd3, 0x28, 0xbb, 0xc9, 0xae, 0x6a, 0xd1, 0x5a, 0x30, 0x90, 0x84, 0xf9, 
            0xb2, 0x58, 0xcf, 0x7e, 0xc5, 0xcb, 0x97, 0xe4, 0x16, 0x6c, 0xfa, 0xb0, 0x6d, 0x1f, 0x52, 0x99, 
            0x0d, 0x4e, 0x03, 0x91, 0xc2, 0x4d, 0x64, 0x77, 0x9f, 0xdd, 0xc4, 0x49, 0x8a, 0x9a, 0x24, 0x38, 
            0xa7, 0x57, 0x85, 0xc7, 0x7c, 0x7d, 0xe7, 0xf6, 0xb7, 0xac, 0x27, 0x46, 0xde, 0xdf, 0x3b, 0xd7, 
            0x9e, 0x2b, 0x0b, 0xd5, 0x13, 0x75, 0xf0, 0x72, 0xb6, 0x9d, 0x1b, 0x01, 0x3f, 0x44, 0xe5, 0x87, 
            0xfd, 0x07, 0xf1, 0xab, 0x94, 0x18, 0xea, 0xfc, 0x3a, 0x82, 0x5f, 0x05, 0x54, 0xdb, 0x00, 0x8b, 
            0xe3, 0x48, 0x0c, 0xca, 0x78, 0x89, 0x0a, 0xff, 0x3e, 0x5b, 0x81, 0xee, 0x71, 0xe2, 0xda, 0x2c, 
            0xb8, 0xb5, 0xcc, 0x6e, 0xa8, 0x6b, 0xad, 0x60, 0xc6, 0x08, 0x04, 0x02, 0xe8, 0xf5, 0x4f, 0xa4, 
            0xf3, 0xc0, 0xce, 0x43, 0x25, 0x1c, 0x21, 0x33, 0x0f, 0xaf, 0x47, 0xed, 0x66, 0x63, 0x93, 0xaa];    
       
       $this->sboxesForDecryption[2]=[                
            0x45, 0xd4, 0x0b, 0x43, 0xf1, 0x72, 0xed, 0xa4, 0xc2, 0x38, 0xe6, 0x71, 0xfd, 0xb6, 0x3a, 0x95, 
            0x50, 0x44, 0x4b, 0xe2, 0x74, 0x6b, 0x1e, 0x11, 0x5a, 0xc6, 0xb4, 0xd8, 0xa5, 0x8a, 0x70, 0xa3, 
            0xa8, 0xfa, 0x05, 0xd9, 0x97, 0x40, 0xc9, 0x90, 0x98, 0x8f, 0xdc, 0x12, 0x31, 0x2c, 0x47, 0x6a, 
            0x99, 0xae, 0xc8, 0x7f, 0xf9, 0x4f, 0x5d, 0x96, 0x6f, 0xf4, 0xb3, 0x39, 0x21, 0xda, 0x9c, 0x85, 
            0x9e, 0x3b, 0xf0, 0xbf, 0xef, 0x06, 0xee, 0xe5, 0x5f, 0x20, 0x10, 0xcc, 0x3c, 0x54, 0x4a, 0x52, 
            0x94, 0x0e, 0xc0, 0x28, 0xf6, 0x56, 0x60, 0xa2, 0xe3, 0x0f, 0xec, 0x9d, 0x24, 0x83, 0x7e, 0xd5, 
            0x7c, 0xeb, 0x18, 0xd7, 0xcd, 0xdd, 0x78, 0xff, 0xdb, 0xa1, 0x09, 0xd0, 0x76, 0x84, 0x75, 0xbb, 
            0x1d, 0x1a, 0x2f, 0xb0, 0xfe, 0xd6, 0x34, 0x63, 0x35, 0xd2, 0x2a, 0x59, 0x6d, 0x4d, 0x77, 0xe7, 
            0x8e, 0x61, 0xcf, 0x9f, 0xce, 0x27, 0xf5, 0x80, 0x86, 0xc7, 0xa6, 0xfb, 0xf8, 0x87, 0xab, 0x62, 
            0x3f, 0xdf, 0x48, 0x00, 0x14, 0x9a, 0xbd, 0x5b, 0x04, 0x92, 0x02, 0x25, 0x65, 0x4c, 0x53, 0x0c, 
            0xf2, 0x29, 0xaf, 0x17, 0x6c, 0x41, 0x30, 0xe9, 0x93, 0x55, 0xf7, 0xac, 0x68, 0x26, 0xc4, 0x7d, 
            0xca, 0x7a, 0x3e, 0xa0, 0x37, 0x03, 0xc1, 0x36, 0x69, 0x66, 0x08, 0x16, 0xa7, 0xbc, 0xc5, 0xd3, 
            0x22, 0xb7, 0x13, 0x46, 0x32, 0xe8, 0x57, 0x88, 0x2b, 0x81, 0xb2, 0x4e, 0x64, 0x1c, 0xaa, 0x91, 
            0x58, 0x2e, 0x9b, 0x5c, 0x1b, 0x51, 0x73, 0x42, 0x23, 0x01, 0x6e, 0xf3, 0x0d, 0xbe, 0x3d, 0x0a, 
            0x2d, 0x1f, 0x67, 0x33, 0x19, 0x7b, 0x5e, 0xea, 0xde, 0x8b, 0xcb, 0xa9, 0x8c, 0x8d, 0xad, 0x49, 
            0x82, 0xe4, 0xba, 0xc3, 0x15, 0xd1, 0xe0, 0x89, 0xfc, 0xb1, 0xb9, 0xb5, 0x07, 0x79, 0xb8, 0xe1];    
       
       $this->sboxesForDecryption[3]=[
            0xb2, 0xb6, 0x23, 0x11, 0xa7, 0x88, 0xc5, 0xa6, 0x39, 0x8f, 0xc4, 0xe8, 0x73, 0x22, 0x43, 0xc3, 
            0x82, 0x27, 0xcd, 0x18, 0x51, 0x62, 0x2d, 0xf7, 0x5c, 0x0e, 0x3b, 0xfd, 0xca, 0x9b, 0x0d, 0x0f, 
            0x79, 0x8c, 0x10, 0x4c, 0x74, 0x1c, 0x0a, 0x8e, 0x7c, 0x94, 0x07, 0xc7, 0x5e, 0x14, 0xa1, 0x21, 
            0x57, 0x50, 0x4e, 0xa9, 0x80, 0xd9, 0xef, 0x64, 0x41, 0xcf, 0x3c, 0xee, 0x2e, 0x13, 0x29, 0xba, 
            0x34, 0x5a, 0xae, 0x8a, 0x61, 0x33, 0x12, 0xb9, 0x55, 0xa8, 0x15, 0x05, 0xf6, 0x03, 0x06, 0x49, 
            0xb5, 0x25, 0x09, 0x16, 0x0c, 0x2a, 0x38, 0xfc, 0x20, 0xf4, 0xe5, 0x7f, 0xd7, 0x31, 0x2b, 0x66, 
            0x6f, 0xff, 0x72, 0x86, 0xf0, 0xa3, 0x2f, 0x78, 0x00, 0xbc, 0xcc, 0xe2, 0xb0, 0xf1, 0x42, 0xb4, 
            0x30, 0x5f, 0x60, 0x04, 0xec, 0xa5, 0xe3, 0x8b, 0xe7, 0x1d, 0xbf, 0x84, 0x7b, 0xe6, 0x81, 0xf8, 
            0xde, 0xd8, 0xd2, 0x17, 0xce, 0x4b, 0x47, 0xd6, 0x69, 0x6c, 0x19, 0x99, 0x9a, 0x01, 0xb3, 0x85, 
            0xb1, 0xf9, 0x59, 0xc2, 0x37, 0xe9, 0xc8, 0xa0, 0xed, 0x4f, 0x89, 0x68, 0x6d, 0xd5, 0x26, 0x91, 
            0x87, 0x58, 0xbd, 0xc9, 0x98, 0xdc, 0x75, 0xc0, 0x76, 0xf5, 0x67, 0x6b, 0x7e, 0xeb, 0x52, 0xcb, 
            0xd1, 0x5b, 0x9f, 0x0b, 0xdb, 0x40, 0x92, 0x1a, 0xfa, 0xac, 0xe4, 0xe1, 0x71, 0x1f, 0x65, 0x8d, 
            0x97, 0x9e, 0x95, 0x90, 0x5d, 0xb7, 0xc1, 0xaf, 0x54, 0xfb, 0x02, 0xe0, 0x35, 0xbb, 0x3a, 0x4d, 
            0xad, 0x2c, 0x3d, 0x56, 0x08, 0x1b, 0x4a, 0x93, 0x6a, 0xab, 0xb8, 0x7a, 0xf2, 0x7d, 0xda, 0x3f, 
            0xfe, 0x3e, 0xbe, 0xea, 0xaa, 0x44, 0xc6, 0xd0, 0x36, 0x48, 0x70, 0x96, 0x77, 0x24, 0x53, 0xdf, 
            0xf3, 0x83, 0x28, 0x32, 0x45, 0x1e, 0xa4, 0xd3, 0xa2, 0x46, 0x6e, 0x9c, 0xdd, 0x63, 0xd4, 0x9d];   
            
            
       $this->mdsMatrix[] = [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04];             
       $this->mdsMatrix[] = [0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07];             
       $this->mdsMatrix[] = [0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06];             
       $this->mdsMatrix[] = [0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08];             
       $this->mdsMatrix[] = [0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01 ];             
       $this->mdsMatrix[] = [0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05];             
       $this->mdsMatrix[] = [0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01];             
       $this->mdsMatrix[] = [0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01];             
       
       $this->mdsInvMatrix[] = [0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA];             
       $this->mdsInvMatrix[] = [0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7];             
       $this->mdsInvMatrix[] = [0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49];             
       $this->mdsInvMatrix[] = [0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F];             
       $this->mdsInvMatrix[] = [0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8];             
       $this->mdsInvMatrix[] = [0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76];             
       $this->mdsInvMatrix[] = [0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95];             
       $this->mdsInvMatrix[] = [0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD];             
       
   
   }

   public  function Init(  $forEncryption, $key=null)
   {  
        //Reset();
       if ($key != null)
       {
            $this->workingKey = $this->BytesToWords($key);

            $kt= Util::alloc($this->nb);

             $kt= $this->BasicKeyExpand($this->workingKey, $kt);

            $this->ExtendedKeyExpand($this->workingKey, $kt);

            $this->KeyExpandOdd();
            
      }
      

       $this->forEncryption = $forEncryption;      
   }
  

   private function BytesToWords($ba) {
    //  506097522914230528
 $dd=  sprintf('%08x', 506097522914230528)  ;
 $dd=    506097522914230528   ;
    
   $words=[];
   $i=0;
   foreach(array_chunk($ba,8) as $part){
       $part = array_reverse($part) ;
       $part = Util::array2hex($part) ;
       $bi=  gmp_init($part, 16);
        
    
        $words[$i++]= new BigInt($bi);
   
        if (false)  //no LE
        {
           //  words[i] = ReverseWord(words[i]);
        }
   }
   
 

   return $words;   
    
  }

   private function WordsToBytes($wa) {

         
               $bytes = Util::alloc(  count($wa) * 8 );

           
               for ($i = 0; $i < count($wa); ++$i)
               {
                    if (false)  //not LE
                    {
                       //  words[i] = ReverseWord(words[i]);
                    }
                    $t = $wa[$i]; 
                    $tempBytes = $t->buf8();

                    $tempBytes = array_reverse($tempBytes) ;
                  
                   
                    for ( $j = 0;  $j < count($tempBytes);  $j++)
                    {
                         $bytes[ ( $i * count($tempBytes) )+ $j] = $tempBytes[$j];
                    }
                   
               }
               return $bytes;
   }  
   
   private function BasicKeyExpand($key,$kt) {
     $k0 = Util::alloc($this->nb)  ;
     $k1 = Util::alloc($this->nb)  ;
     
     $this->internalState = [] ;
     for($i=0;$i<$this->nb ;$i++ ) {
        $this->internalState[$i] = BigInt::fromInt(0) ;
     }
     $this->internalState[0]  = BigInt::fromInt($this->nb + $this->nk + 1);

     if ($this->nb == $this->nk)
     {
          for($i=0;$i<count($k0) ;$i++) {
              $k0[$i]= $key[$i];
          }
          for($i=0;$i<count($k1) ;$i++) {
              $k1[$i]= $key[$i];
          }
     
     }
     else
     {
          for($i=0;$i< $this->nb ;$i++) {
              $k0[$i]= $key[$i];
          }
          for($i=0;$i<$this->nb ;$i++) {
              $k1[$i]= $key[$this->nb+$i];
          }         
     }   

      $this->AddRoundKeyExpand($k0);
      $this->EncryptionRound();
      $this->XorRoundKeyExpand($k1);
      $this->EncryptionRound();
      $this->AddRoundKeyExpand($k0);
      $this->EncryptionRound();
              
         
       for($i=0;$i < $this->nb ;$i++) {
          $kt[$i]= $this->internalState[$i];
       }  
                        
      return $kt;  
   }
  
   private function ExtendedKeyExpand($key,$kt) {
  
               $initial_data = Util::alloc($this->nk)  ;
               $kt_round = Util::alloc($this->nb)   ;
               $tmv =  Util::alloc($this->nb)    ;
               $round = 0;
             
               for (  $i = 0; $i < $this->nk; $i++)
               {
                    $initial_data[$i] = $key[$i];
               }  
               for (  $i = 0; $i < $this->nb; $i++)
               {
                    $tmv[$i] =  BigInt::fromString('0x0001000100010001');
               }  
               

               while (true)
               {
                   for (  $i = 0; $i < $this->nk; $i++)
                   {
                        $this->internalState[$i] = $kt[$i];
                   }
   
                   $this->AddRoundKeyExpand($tmv);

                   for (  $i = 0; $i < $this->nb; $i++)
                   {
                       $kt_round[$i] = $this->internalState[$i];
                   }
                   for (  $i = 0; $i < $this->nb; $i++)
                   {
                        $this->internalState[$i] = $initial_data[$i];
                   }
                    
                   $this->AddRoundKeyExpand($kt_round);
                   $this->EncryptionRound();
                   $this->XorRoundKeyExpand($kt_round);
                   $this->EncryptionRound();
                   $this->AddRoundKeyExpand($kt_round);
            

                   for (  $i = 0; $i < $this->nb; $i++)
                   {
                        $this->roundKeys[$round][$i] = $this->internalState[$i];
                   }
                       
                    
                    if ($this->roundKeysAmount == $round)
                    {
                         break;
                    }  
                    
                    if ($this->nk != $this->nb)
                    {
                         $round += 2;
                         //todo
                    }
                    $round += 2;
                    $tmv = $this->ShiftLeft($tmv);


                    $temp = $initial_data[0];

                    for (  $i = 0; $i < count($initial_data); $i++)
                    {
                        $initial_data[$i] =  $initial_data[$i+1];
                    }    
                    $initial_data[count($initial_data) - 1] = $temp;
                      
               }
                  
   }
 
   private function KeyExpandOdd( ) {
      for (  $i = 1; $i < $this->roundKeysAmount; $i += 2)
      {
            //      Array.Copy(roundKeys[i - 1], roundKeys[i], nb);
          
           for (  $j = 0; $j < $this->nb; $j++)
           {
                $this->roundKeys[$i]  = $this->roundKeys[$i-1]   ;
           }
         //  for (  $j = 0; $j < $this->nb; $j++)
           {
            //  for (  $k = 0; $k < count($this->roundKeys[$i-1+$j]); $k++)
              {
               // $this->roundKeys[$i+$j][$k]    = $this->roundKeys[$i-1+$j][$k]  ;
                
              }               
           }               
            
           $this->roundKeys[$i] = $this->RotateLeft($this->roundKeys[$i]);
      }     
   }  

   private function RotateLeft( $state_value ) {
      
      
               $rotateBytesLength = 2 * count($state_value) + 3;
               $bytesLength = count($state_value) * (self::BITS_IN_WORD / self::BITS_IN_BYTE);
            

               $bytes = $this->WordsToBytes($state_value);
               $buffer = Util::alloc($bytesLength);

            
               for ($i = 0; $i < $rotateBytesLength; $i++)
               {
                   $buffer[$i] = $bytes[$i]  ;
               }     
 
               for ($i = 0; $i < $bytesLength - $rotateBytesLength; $i++)
               {
                   $bytes[$i] = $bytes[$i+$rotateBytesLength]  ;
               }     
 
               for ($i = 0; $i < $rotateBytesLength; $i++)
               {
                   $bytes[$i+$bytesLength - $rotateBytesLength] = $buffer[$i ]  ;
               }     

               $temp = $this->BytesToWords($bytes);
              
               for ($i = 0; $i < count($state_value); $i++)
               {
                   $state_value[$i] = $temp[$i]  ;
               }     
  
          return $state_value;
   }  

   private function AddRoundKey($round) {
       for ($i = 0; $i < $this->nb; ++$i)
       {
           $tmp = $this->internalState[$i]   ;
           $this->internalState[$i] = $tmp->add($this->roundKeys[$round][$i]);
       }     
   }
   private function XorRoundKey($round) {
       for ($i = 0; $i < $this->nb; $i++)
       {
           $this->internalState[$i] = $this->internalState[$i]->xor($this->roundKeys[$round][$i]);
       }     
   }
   private function AddRoundKeyExpand($value) {
      for ($i = 0; $i < $this->nb; $i++)
      {
           $this->internalState[$i] = $this->internalState[$i]->add( $value[$i] );
      }      
   }
  
   private function EncryptionRound( ) {
      $this->SubBytes();
      $this->ShiftRows();
      $this->MixColumns();    
   }
 
   private function XorRoundKeyExpand($value ) {
      for (  $i = 0; $i < $this->nb; $i++)
      {
          $this->internalState[$i] = $this->internalState[$i]->xor( $value[$i]);
      }       
   }

   private function SubRoundKey($round ) {
      for (  $i = 0; $i < $this->nb; ++$i)
      {
          $t=  $this->internalState[$i]->sub( $this->roundKeys[$round][$i]) ;
          $this->internalState[$i] = $t;
      }   
    
   }

   private function DecryptionRound(  ) {
         $this->InvMixColumns();
         $this->InvShiftRows();
         $this->InvSubBytes();
    
   }
   private function InvMixColumns(  ) {
         $this->MatrixMultiply( $this->mdsInvMatrix); 
   }
   private function InvShiftRows(  ) {
       
          
           $shift = -1;

           $stateBytes = $this->WordsToBytes($this->internalState);
           $nstate= Util::alloc($this->nb * 8); 

           for ($row = 0; $row < 8; $row++)
           {
                if ($row % (8 / $this->nb) == 0)
                {
                     $shift += 1;
                }

                for ($col = 0; $col < $this->nb; $col++)
                {
                     $nstate[$row + $col * 8] = $stateBytes[$row + (($col + $shift) % $this->nb) * 8];
                }
           }

           $this->internalState = $this->BytesToWords($nstate); 
              
   }
   private function InvSubBytes(  ) {
             /*
               for (int i = 0; i < nb; i++)
               {
                    internalState[i] = sboxesForDecryption[0][internalState[i] & 0x00000000000000FF] |
                               ((ulong)sboxesForDecryption[1][(internalState[i] & 0x000000000000FF00) >> 8] << 8) |
                               ((ulong)sboxesForDecryption[2][(internalState[i] & 0x0000000000FF0000) >> 16] << 16) |
                               ((ulong)sboxesForDecryption[3][(internalState[i] & 0x00000000FF000000) >> 24] << 24) |
                               ((ulong)sboxesForDecryption[0][(internalState[i] & 0x000000FF00000000) >> 32] << 32) |
                               ((ulong)sboxesForDecryption[1][(internalState[i] & 0x0000FF0000000000) >> 40] << 40) |
                               ((ulong)sboxesForDecryption[2][(internalState[i] & 0x00FF000000000000) >> 48] << 48) |
                               ((ulong)sboxesForDecryption[3][(internalState[i] & 0xFF00000000000000) >> 56] << 56);
               }  
               */ 
               
      for ($i = 0; $i < $this->nb; $i++)
      {
          
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00000000000000FF")) ;
                 $tmpi = $tmp->toInt() ;
                 $v0=BigInt::fromInt( $this->sboxesForDecryption[0][$tmpi] );
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("000000000000FF00"))->shiftRight(8)  ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[1][$tmpi] );
                 $v1 =  $tmp->shiftLeft(8);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("0000000000FF0000"))->shiftRight(16) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[2][$tmpi] );
                 $v2 =  $tmp->shiftLeft(16);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00000000FF000000"))->shiftRight(24) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[3][$tmpi] );
                 $v3 =  $tmp->shiftLeft(24);
              
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("000000FF00000000"))->shiftRight(32) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[0][$tmpi] );
                 $v4 =  $tmp->shiftLeft(32);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("0000FF0000000000"))->shiftRight(40) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[1][$tmpi] );
                 $v5 =  $tmp->shiftLeft(40);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00FF000000000000"))->shiftRight(48) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[2][$tmpi] );
                 $v6 =  $tmp->shiftLeft(48);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("FF00000000000000"))->shiftRight(56)  ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForDecryption[3][$tmpi] );
                 $v7 =  $tmp->shiftLeft(56);

                 $this->internalState[$i] = $v0->or($v1)->or($v2)->or($v3)->or($v4)->or($v5)->or($v6)->or($v7) ;
             
                
      }                
               
   }
   
   private function SubBytes( ) {
      for ($i = 0; $i < $this->nb; $i++)
      {
          
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00000000000000FF")) ;
                 $tmpi = $tmp->toInt() ;
                 $v0=BigInt::fromInt( $this->sboxesForEncryption[0][$tmpi] );
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("000000000000FF00"))->shiftRight(8)  ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[1][$tmpi] );
                 $v1 =  $tmp->shiftLeft(8);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("0000000000FF0000"))->shiftRight(16) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[2][$tmpi] );
                 $v2 =  $tmp->shiftLeft(16);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00000000FF000000"))->shiftRight(24) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[3][$tmpi] );
                 $v3 =  $tmp->shiftLeft(24);
              
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("000000FF00000000"))->shiftRight(32) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[0][$tmpi] );
                 $v4 =  $tmp->shiftLeft(32);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("0000FF0000000000"))->shiftRight(40) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[1][$tmpi] );
                 $v5 =  $tmp->shiftLeft(40);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("00FF000000000000"))->shiftRight(48) ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[2][$tmpi] );
                 $v6 =  $tmp->shiftLeft(48);
                 $tmp = $this->internalState[$i]->and(BigInt::fromString("FF00000000000000"))->shiftRight(56)  ;
                 $tmpi = $tmp->toInt() ;
                 $tmp=BigInt::fromInt( $this->sboxesForEncryption[3][$tmpi] );
                 $v7 =  $tmp->shiftLeft(56);

                 $this->internalState[$i] = $v0->or($v1)->or($v2)->or($v3)->or($v4)->or($v5)->or($v6)->or($v7) ;
             
                
      }        
   } 
 
   private function ShiftRows( ) {
               
               $shift = -1;

               $stateBytes = $this->WordsToBytes($this->internalState);

               $nstate = Util::alloc( $this->nb * 8 );

               for ($row = 0; $row < 8; $row++)
               {
                    if ($row % (8 / $this->nb) == 0)
                    {
                         $shift += 1;
                    }

                    for ( $col = 0;  $col < $this->nb;  $col++)
                    {
                         $nstate[$row + (($col + $shift) % $this->nb) * 8] = $stateBytes[$row + $col * 8];
                    }
               }

               $this->internalState = $this->BytesToWords($nstate);      
   } 
 
   private function MixColumns( ) {
       $this->MatrixMultiply($this->mdsMatrix);     
   } 
 
   private function ShiftLeft($state_value ) {
 
          for (  $i = 0; $i < count($state_value); $i++)
          {
              $state_value[$i] = $state_value[$i]->shiftLeft(1);
          }
          $state_value=   array_reverse($state_value);
          return $state_value;
   } 
 
  
   private function MatrixMultiply(  $matrix)
  {
 
       
    
       $stateBytes = $this->WordsToBytes($this->internalState);



       for ($col = 0; $col < $this->nb; ++$col)
       {
            $result = BigInt::fromInt(0);
            for ($row = 8 - 1; $row >= 0; --$row)
            {
                 $product = 0;
                 for ($b = 8 - 1; $b >= 0; --$b)
                 {
                      $t =  $this->MultiplyGF($stateBytes[$b + $col * 8], $matrix[$row][$b]);
                      $product ^= $t;
                     

                 }
                 $p=BigInt::fromInt($product)   ;
                 $p = $p->shiftLeft($row * 8);
                        
                 $result =  $result->or($p);
 
            }
            
            $this->internalState[$col] = $result;
       }

    
  } 
 
   private function MultiplyGF(  $x,$y) {
 
       $r = 0;
       $hbit = 0;

       for (  $i = 0; $i < self::BITS_IN_BYTE; $i++)
       {
            if (($y & 0x01) == 1)
            {
                 $r ^= $x;
            }

            $hbit =  ($x & 0x80);

            $x <<= 1;

            if ($hbit == 0x80)
            {
                 $x =  $x ^ self::REDUCTION_POLYNOMIAL;
            }
            $y >>= 1;
       }
       return $r;     
  }   
 
   private function Encrypt($plain, $inOff, $cipherText, $outOff)  {  
   
         $round = 0;
       
         for($i=0;$i< $this->blockSizeBits / self::BITS_IN_BYTE ;$i++ ) {
                $plain[$i] = $plain[$inOff+$i]  ;
         }    
        $plain_ = $this->BytesToWords($plain);

  
        for($i=0;$i< $this->nb  ;$i++ ) {
            $this->internalState[$i] = $plain_[$inOff+$i]  ;
        }    

        $this->AddRoundKey($round);

    
        for ($round = 1; $round < $this->roundKeysAmount; $round++)
        {
             $this->EncryptionRound();

             $this->XorRoundKey($round);

        }
        $this->EncryptionRound();

        $this->AddRoundKey($this->roundKeysAmount);

        $cipherText_=[];

        for($i=0;$i< $this->nb  ;$i++ ) {
            $cipherText_[$i] = $this->internalState[$inOff+$i]  ;
        }    

        $temp = $this->WordsToBytes($cipherText_);

        for($i=0;$i< count($temp)  ;$i++ ) {
            $cipherText[$outOff+$i] = $temp[ $i]  ;
        }    

          
        return $cipherText;
   }
      
   private function Decrypt($cipherText, $inOff, $decryptedText=[], $outOff=0)    {
      
        for($i=0;$i< $this->blockSizeBits / self::BITS_IN_BYTE  ;$i++ ) {
            $cipherText[ $i] = $cipherText[ $i+$inOff]  ;
        } 
      
       
        $round = $this->roundKeysAmount;

        $cipherText_ = $this->BytesToWords($cipherText);

        for($i=0;$i< $this->nb  ;$i++ ) {
            $this->internalState[ $i] = $cipherText_[ $i]  ;
        } 
    
        
        $this->SubRoundKey($round);
        
        for ($round = $this->roundKeysAmount - 1; $round > 0; $round--)
        {
             $this->DecryptionRound();

         
             $this->XorRoundKey($round);
        }

        $this->DecryptionRound();
        $this->SubRoundKey(0);
    

        $decryptedText_ = [];

      
        for($i=0;$i< $this->nb  ;$i++ ) {
            $decryptedText_[ $i] = $this->internalState[ $i]  ;
        } 

        $temp = $this->WordsToBytes($decryptedText_);
       
        for($i=0;$i< count($temp)  ;$i++ ) {
           $decryptedText[ $i+$outOff] = $temp[ $i]  ;
        }    
        return $decryptedText;
   }
      
 
   private function ProcessBlock(  $input, $inOff, $output=[], $outOff=0) {
         
             
               if ($this->forEncryption)
               {
                  $output  =  $this->Encrypt($input, $inOff, $output, $outOff);
               }
               else
               {
                  $output =   $this->Decrypt($input, $inOff, $output, $outOff);
               }
                

                 
               return [$this->GetBlockSize(),$output];
                  
         
   }


   private function GetBlockSize() {
       return $this->blockSizeBits / self::BITS_IN_BYTE;
   }
   
   public function ProcessBytes($input ) {
       $inOff=9;
       $length=count($input);
       if($length==0)  {
            throw new  \InvalidArgumentException("Emtpy data");
       }

      
       $outOff=0;
       $output=[];
        
       $blockSize = $this->GetBlockSize();
       $this->buf = Util::alloc($blockSize);
   
    
       $total = $length + $this->bufOff;
       $leftOver = $total % count($this->buf );
       $outLength= $total - $leftOver;
       
 
       $resultLen = 0;
       $gapLen = count($this->buf ) - $bufOff;
       if ($length > $gapLen)
       {
         //   Array.Copy(input, inOff, buf, bufOff, gapLen);
             for($i=0;$i<$gapLenh ;$i++ ) {
                $this->buf[$i] = $input[$i]  ;
             }  
          
            list($r1,$output) = $this->ProcessBlock($this->buf, 0 );
            $resultLen += $r1;
            $outOff = 0;
            $length -= $gapLen;
            $inOff += $gapLen;
            while ($length > count($this->buf ))
            {
                 list($r1,$output) =  $this->ProcessBlock($input, $inOff,$output,$length );
                 
                 $resultLen += $rl; 
                 $length -= $blockSize;
                 $inOff += $blockSize;
            }
       }

         //   Array.Copy(input, inOff, buf, bufOff, length);
       for($i=0;$i<$length ;$i++ ) {
           $this->buf[$i] = $input[$i]  ;
       }
 
       $this->bufOff += $length;
       if ( $this->bufOff == count($this->buf ))
       {
          list($r1,$output) = $this->ProcessBlock($this->buf, 0 , $output,  $outOff + $resultLen);
          $resultLen += $r1;
          $this->bufOff = 0;
       }

       
       return [ $resultLen,$output];  
   }

   public function DoFinal( $output,  $outOff) {
       
   if ($this->bufOff != 0)
   {
      
     
     list($r1,$output) =   $this->ProcessBlock($output, 0 );
                            
     // Array.Copy(buf, 0, output, outOff, bufOff);
                          
 }

    
       
      return $output; 
   }   
   
   
}


class BigInt
{
    private $value = null;
    public $dec = null;
    public $hex = null;

   
    public function __construct(  $v=null  )     {
        if($v!=null) {
           $this->setValue($v);     
        }
      
      
    }
    public static function fromString($str, $base=16){
        $f = new BigInt();
       
        $f->setValue(gmp_init($str, $base));   
        return $f;
    }  
    public static function fromInt($v=0 ){
        $f = new BigInt();
        $f->setValue(gmp_init((int)$v));   
        return $f;
    }
 
    public function toString($base = 10){
        return gmp_strval($this->value, $base);
    }

 
    private function setValue($v){
       $this->value = $v;
       //для отладки
    //   $this->dec = gmp_strval($this->value, 10); 
     //  $this->hex = gmp_strval($this->value, 16); 
    }
   
    public   function add($v ){
        $f = new BigInt();
      
        $f->setValue(gmp_add($this->value, $v->value) );
        
        $c= gmp_cmp($f->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16) )  ;
        if($c>0) {
          $f->setValue(gmp_sub($f->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16)) );
          $f->setValue(gmp_sub($f->value, gmp_init("0x1", 16)) );
        }                       
        if($c<0) {
        //  $f->setValue(gmp_sub($this->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16)) );
        }  
        
        if($c==0) {
           //$f->setValue(gmp_sub($this->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16)) );
        }  
        
        return $f;      
    }
    
    public   function sub($v ){
        $f = new BigInt();
      
        $f->setValue(gmp_sub($this->value, $v->value) );
        
        $c= gmp_cmp($f->value, gmp_init(0) )  ;
        if($c>0) {

        }                       
        if($c<0) {
          $f->setValue(gmp_add($f->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16)) );
          $f->setValue(gmp_add($f->value, gmp_init("0x1", 16)) );
         
        }  
        
        if($c==0) {
          //$f->setValue(gmp_sub($this->value, gmp_init("0xFFFFFFFFFFFFFFFF", 16)) );
        }  
        
        return $f;      
    }

    public   function and($v ){
        $f = new BigInt();
        $f->setValue(gmp_and($this->value, $v->value) );
        return $f;      
    }

    public   function or($v ){
        $f = new BigInt();
        $f->setValue(gmp_or($this->value, $v->value) );
        return $f;      
    }

    public   function xor($v ){
        $f = new BigInt();
        $f->setValue(gmp_xor($this->value, $v->value) );
        return $f;      
    }
    
    public   function toInt(){
      return   gmp_intval($this->value) ;
    }

    public function shiftLeft($n){
        if ($n < 0) {
            throw new  \InvalidArgumentException("Shift amount cannot be negative.");
        }

        $value = $this->value;
        while ($n > 0) {
            $step = min($n, 32); //  используем меньшие  шаги для  сдвига
            $value = gmp_mul($value, gmp_pow(2, $step));
            $n -= $step;
        }

        $f = new BigInt();
        $f->setValue($value)   ;
    
        return $f;
    }

 
    public function shiftRight($n){
        if ($n < 0) {
            throw new \InvalidArgumentException("Shift amount cannot be negative.");
        }

        $value = $this->value;
        while ($n > 0) {
            $step = min($n, 32); // используем меньшие  шаги для  сдвига
            $value = gmp_div_q($value, gmp_pow(2, $step));
            $n -= $step;
        }
           
        $f = new BigInt();
        $f->setValue($value)   ;
        return $f;
    }
    
    public function buf8(){
        $s=  $this->toString(16)  ;
        $isOdd = (strlen($s) % 2 != 0) ;
        if($isOdd){
          $s = "0".$s  ;
        }
        $a2= str_split($s,2) ;
        $buf=[];
        foreach($a2 as $i) {
           $buf[]= hexdec($i) ;  
        }      
       
        return $buf;
    }   
}