#include <iostream>
#include <bitset>
#include <cstring>
#include <cmath>
#include <algorithm>

// school stuff

/* #ifndef MARMOSET_TESTING
int main();
#endif
char *encode( char *plaintext, unsigned long key );
char *decode( char *ciphertext, unsigned long key ); */

#ifndef MARMOSET_TESTING
int main() {
  char str[] = {"Hello world!"};
  char str1[] = {"A Elbereth Gilthoniel\nsilivren penna miriel\n"
  "o menel aglar elenath!\nNa-chaered palan-diriel\n"
  "o galadhremmin ennorath,\nFanuilos, le linnathon\n"
  "nef aear, si nef aearon!"};
  unsigned long key = 51323;

  std::cout << "\"" << str << "\"" << std::endl;

  char *ciphertext{encode(str, key)};

  std::cout << "\"" << ciphertext << "\"" << std::endl;

  char *plaintext{decode(ciphertext, key)};

  std::cout << "\"" << plaintext << "\"" <<std::endl;

  delete[] ciphertext;
  ciphertext = nullptr;
  delete[] plaintext;
  plaintext = nullptr;

  std::cout << "\"" << str1 << "\"" << std::endl;

  ciphertext = encode(str1, key);

  std::cout << "\"" << ciphertext << "\"" << std::endl;

  plaintext = decode(ciphertext, key);

  std::cout << "\"" << plaintext << "\"" <<std::endl;

  delete[] ciphertext;
  ciphertext = nullptr;
  delete[] plaintext;
  plaintext = nullptr;

  char str3[] = { "....a string of size 1 000 000 bytes...."};
  plaintext = encode(str3, 51231);
  std::cout << "\"" << plaintext << "\"" <<std::endl;
  delete[] plaintext;
  plaintext = nullptr;
  return 0;
}
#endif

char *encode( char *plaintext, unsigned long key ) {
  //find required number of bytes
  std::size_t bytes = 4*ceil(strlen(plaintext)/4.0);

  //make new array with extra null characters if necessary
  unsigned char roundedtext[bytes];
  for (std::size_t ctr = 0; ctr < strlen(plaintext); ctr++){
    roundedtext[ctr] = plaintext[ctr];
  }
  for (std::size_t ctr = strlen(plaintext); ctr < bytes; ctr++){
    roundedtext[ctr] = '\0';
  }
  //declare and shuffle state array
  unsigned char s[256];
  //prefill array
  for (int l = 0; l < 256; l++) {
    s[l] = (unsigned int)l;
  }
  int i = 0;
  int j = 0;
  for (int ctr = 0; ctr < 256; ctr++) {
    int k = i % 64;
    j = (j + s[i] + ((key >> k) & 1));
    j%=256;
    std::swap(s[i], s[j]);
    i++;
    i%=256;
  }

  //xor rounded text with R
  unsigned char xortext[bytes];
  for (size_t ctr = 0; ctr < bytes; ctr++) {
    i++;
    i%=256;
    j = (j + s[i])%256;
    std::swap(s[i], s[j]);
    unsigned long r = (s[i] + s[j])%256;
    unsigned long R = s[r];
    xortext[ctr] =(int)roundedtext[ctr] ^ R;
  }

  //converting to ascii armour
  std::string asciitext= "";
  for (std::size_t ctr = 0; ctr < ((bytes)/ 4); ++ctr)
  {
      //get decimal value
      unsigned int value = 0;
      for (int x = 0; x< 4; x++){
        value += static_cast<unsigned char>(xortext[(4*ctr)+x]) << (3-x)*8;
      }

      //convert to 5 char set of base 85
      std::string fivecharset= "";
      for (int z = 0; z <5; z++) {
        char c = '!' + (value % static_cast<unsigned char>(85));
        fivecharset += c;
        value /= 85;
      }

      //insert into beginning of asciitext
      asciitext.insert(0, fivecharset);
  }

  //put asciitext into pointer array, backwards
  char* cipherarray = new char[asciitext.length() + 1];
  for (std::size_t ctr = asciitext.length(); ctr > 0; ctr--) {
    cipherarray[asciitext.length() - ctr] = asciitext[ctr - 1];
  }
  //add final null pointer
  cipherarray[asciitext.length()] = '\0';

  return cipherarray;
}

char *decode( char *ciphertext, unsigned long key ){

  //Declaring state array
  unsigned char s[256];
  for (int l = 0; l < 256; l++) {
    s[l] = (unsigned int)l;
  }

  //Shuffle state array
  long i = 0;
  long j = 0;
  for (int ctr = 0; ctr < 256; ctr++) {
    int k = i % 64;
    j = (j + s[i] + ((key >> k) & 1));
    j%=256;
    std::swap(s[i], s[j]);
    i++;
    i%=256;
  }
  //Get bytes from ciphertext
  std::reverse( ciphertext, &ciphertext[ strlen( ciphertext ) ] );
  unsigned int value = 0;
  std::string plaintext = "";
  for (std::size_t ctr = 0; ctr < ((strlen(ciphertext))/ 5); ++ctr) {
    //get decimal value
    value = (int)(ciphertext[5*ctr] -33)
    + (int)(85*(ciphertext[(5*ctr) + 1] -33))
    + (int)(85*85*(ciphertext[(5*ctr) + 2] -33))
    + (int)(85*85*85*(ciphertext[(5*ctr) + 3] -33))
    + (int)(85*85*85*85*(ciphertext[(5*ctr) + 4] -33L));
    std::cout << "CTR [" << ctr << "]: " << value <<std::endl;
    //get 4 characters from dec value
    std::string set = "xxxx";
    for (int i = 0; i < 4; i++) {
      unsigned char c = value & 255;
      set[3-i] = c;
      value >>= 8;
    }
    plaintext.insert(0, set);
  }

  //put plaintext into pointer array
  std::size_t size = plaintext.length();
  char *decodedtext = new char[size + 1];
  for (std::size_t i = 0; i < size; i++) {
    decodedtext[i] = plaintext[i];
  }

  //xor the text with R
  for (size_t ctr = 0; ctr < size; ctr++) {
    i++;
    i%=256;
    j = (j + s[i])%256;
    std::swap(s[i], s[j]);
    unsigned long r = (s[i] + s[j])%256;
    unsigned long R = s[r];
    decodedtext[ctr] = (int)decodedtext[ctr] ^ R;
  }

  //Add final null ptr
  decodedtext[size] = '\0';

  return decodedtext;
}
