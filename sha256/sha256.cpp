#include <iostream>
#include <cstring>
#include <iomanip>
#include <byteswap.h>
#include <assert.h>
#include <chrono>

const int BITS_IN_BYTE = 8;

class Word {
private:
	static const unsigned int BYTE_SIZE = 4;
	static const unsigned int BIT_SIZE = 32;
	unsigned int mValue;
public:
	Word() {
		mValue = 0;
	}

	Word(unsigned int input) {
		mValue = input;
	}

	Word(unsigned char* input) {
		updateValueFromBigEndian(input);
	}

	void updateValueFromBigEndian(unsigned char* input) {
		unsigned char* tmp = (unsigned char*) &mValue;
		tmp[3] = input[0];
		tmp[2] = input[1];
		tmp[1] = input[2];
		tmp[0] = input[3];
	}

	const unsigned int getValue() const {
		return mValue;
	}

	Word rotateLeft(unsigned int offset) {
		assert(offset < BIT_SIZE);
		return Word((mValue << offset) | (mValue >> (BIT_SIZE - offset)));
	}

	Word rotateRight(unsigned int offset) {
		assert(offset < BIT_SIZE);
		return Word((mValue >> offset) | (mValue << (BIT_SIZE - offset)));
	}

	Word operator^(Word other) {
		return Word(mValue ^ other.mValue);
	}

	Word operator&(Word other) {
		return Word(mValue & other.mValue);
	}

	Word operator>>(unsigned int offset) {
		return Word(mValue >> offset);
	}

	Word operator<<(unsigned int offset) {
		return Word(mValue << offset);
	}

	Word operator+(Word other) {
		return Word(mValue + other.mValue);
	}

	void operator+=(Word other) {
		mValue += other.mValue;
	}

	Word operator~() {
		return Word(~mValue);
	}

};

class SHA256 {
private:
	Word sha256[8];
public:
	SHA256(Word h0, Word h1, Word h2, Word h3, Word h4, Word h5, Word h6, Word h7) {
		sha256[0] = h0;
		sha256[1] = h1;
		sha256[2] = h2;
		sha256[3] = h3;
		sha256[4] = h4;
		sha256[5] = h5;
		sha256[6] = h6;
		sha256[7] = h7;
	}

	const Word * get() const {
		return sha256;
	}
};

const Word H0 = Word(0x6a09e667);
const Word H1 = Word(0xbb67ae85);
const Word H2 = Word(0x3c6ef372);
const Word H3 = Word(0xa54ff53a);
const Word H4 = Word(0x510e527f);
const Word H5 = Word(0x9b05688c);
const Word H6 = Word(0x1f83d9ab);
const Word H7 = Word(0x5be0cd19);

const Word K[64] = {
		Word(0x428a2f98), Word(0x71374491), Word(0xb5c0fbcf), Word(0xe9b5dba5), Word(0x3956c25b), Word(0x59f111f1), Word(0x923f82a4), Word(0xab1c5ed5),
		Word(0xd807aa98), Word(0x12835b01), Word(0x243185be), Word(0x550c7dc3), Word(0x72be5d74), Word(0x80deb1fe), Word(0x9bdc06a7), Word(0xc19bf174),
		Word(0xe49b69c1), Word(0xefbe4786), Word(0x0fc19dc6), Word(0x240ca1cc), Word(0x2de92c6f), Word(0x4a7484aa), Word(0x5cb0a9dc), Word(0x76f988da),
		Word(0x983e5152), Word(0xa831c66d), Word(0xb00327c8), Word(0xbf597fc7), Word(0xc6e00bf3), Word(0xd5a79147), Word(0x06ca6351), Word(0x14292967),
		Word(0x27b70a85), Word(0x2e1b2138), Word(0x4d2c6dfc), Word(0x53380d13), Word(0x650a7354), Word(0x766a0abb), Word(0x81c2c92e), Word(0x92722c85),
		Word(0xa2bfe8a1), Word(0xa81a664b), Word(0xc24b8b70), Word(0xc76c51a3), Word(0xd192e819), Word(0xd6990624), Word(0xf40e3585), Word(0x106aa070),
		Word(0x19a4c116), Word(0x1e376c08), Word(0x2748774c), Word(0x34b0bcb5), Word(0x391c0cb3), Word(0x4ed8aa4a), Word(0x5b9cca4f), Word(0x682e6ff3),
		Word(0x748f82ee), Word(0x78a5636f), Word(0x84c87814), Word(0x8cc70208), Word(0x90befffa), Word(0xa4506ceb), Word(0xbef9a3f7), Word(0xc67178f2)
};	

SHA256 sha256(const unsigned char* msg, const unsigned long msgLen) {
	const unsigned long msgLenWithPadding = msgLen + 1 + 8;
	const unsigned long chunkNumber = (msgLenWithPadding - 1) / 64 + 1;
	const unsigned long paddingFromByte = msgLen % 64;
	const unsigned long paddingFromChunk = paddingFromByte >= 56 ? chunkNumber - 2 : chunkNumber - 1;
	unsigned char paddedMsg[chunkNumber][64];
	memset(paddedMsg, 0, chunkNumber * 64);
	if (msgLen > 0) memcpy(paddedMsg, msg, msgLen);
	const unsigned long msgLenBits = msgLen * BITS_IN_BYTE;
	memcpy(&paddedMsg[chunkNumber - 1][56], &msgLenBits, 8);

	// Append message length at the end, in big endian
	for (int i = 0; i < 4; ++i) {
		unsigned char tmp = paddedMsg[chunkNumber - 1][56 + i];
		paddedMsg[chunkNumber - 1][56 + i] = paddedMsg[chunkNumber - 1][63 - i];
		paddedMsg[chunkNumber - 1][63 - i] = tmp;
	}
	paddedMsg[paddingFromChunk][paddingFromByte] = 0x80;
	
	Word msgWrd[chunkNumber][16];
	for (int chunkNo = 0; chunkNo < chunkNumber; ++chunkNo) {
		for (int i = 0; i < 16; ++i) {
			msgWrd[chunkNo][i] = Word(&paddedMsg[chunkNo][4 * i]);
		}
	}

	Word h0 = H0;
	Word h1 = H1;
	Word h2 = H2;
	Word h3 = H3;
	Word h4 = H4;
	Word h5 = H5;
	Word h6 = H6;
	Word h7 = H7;

	for (int chunkNo = 0; chunkNo < chunkNumber; ++chunkNo) {
		Word w[64];
		memcpy(w, msgWrd[chunkNo], 16 * sizeof(Word));
		for (int i = 16; i < 64; ++i) {
			Word s0 = w[i - 15].rotateRight( 7) ^ w[i - 15].rotateRight(18) ^ (w[i - 15] >>  3);
			Word s1 = w[i -  2].rotateRight(17) ^ w[i -  2].rotateRight(19) ^ (w[i -  2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		Word a = h0;
		Word b = h1;
		Word c = h2;
		Word d = h3;
		Word e = h4;
		Word f = h5;
		Word g = h6;
		Word h = h7;

		for (int i = 0; i < 64; ++i) {
			Word S1 = e.rotateRight(6) ^ e.rotateRight(11) ^ e.rotateRight(25);
			Word ch = (e & f) ^ ((~e) & g);
			Word temp1 = h + S1 + ch + K[i] + w[i];
			Word S0 = a.rotateRight(2) ^ a.rotateRight(13) ^ a.rotateRight(22);
			Word maj = (a & b) ^ (a & c) ^ (b & c);
			Word temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;

	}

	return SHA256(h0, h1, h2, h3, h4, h5, h6, h7);

}

double benchmarkMhs(unsigned short targetLeadingZeros) {
	assert(targetLeadingZeros <= 8);
	const unsigned long len = 40;
        unsigned char msg[len] = {0};
	unsigned long nonce = 0;
        auto start = std::chrono::system_clock::now();
        SHA256 hash = sha256(msg, len);
        do {
                nonce += 1;
                memcpy(msg, &nonce, 8);
                hash = sha256(msg, len);
        } while (hash.get()[0].getValue() > 0xffffffff >> targetLeadingZeros * 4);

        auto end = std::chrono::system_clock::now();
        long elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        return 1. * nonce / elapsed;
}





int main(int argc, char* argv[]) {


	std::cout << benchmarkMhs(7) << "MH/s" << std::endl;


	/*	
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[0].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[1].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[2].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[3].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[4].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[5].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[6].getValue() << " ";
	std::cout << std::hex << std::setfill('0') << std::setw(8) << hash.get()[7].getValue() << " ";
	std::cout << std::endl; */
	return 0;
}

