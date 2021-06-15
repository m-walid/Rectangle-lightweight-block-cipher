class Rectangle {
  constructor(plainText, key) {
    this.plainText = new Uint16Array(plainText);
    this.cipherText = new Uint16Array(plainText);
    this.key = new Uint16Array(key);
    this.mainKey = new Uint16Array(key);
    this.rc = 0;
  }

  clsh(num, shift) {
    const newNum = num.toString(2).padStart(16, "0").split("");
    return parseInt(
      [...newNum.slice(shift), ...newNum.slice(0, shift)].join(""),
      2
    );
  }

  generateRC(rc) {
    if (rc === 0) {
      rc = 1;
    } else {
      let rc0 = (rc & 0x10) ^ (rc & 0x04);
      rc <<= 1;
      rc &= 0x1f;
      rc |= rc0;
    }
    this.rc = rc;
  }

  sBox(num) {
    const sBoxTable = [
      0x06, 0x05, 0x0c, 0x0a, 0x01, 0x0e, 0x07, 0x09, 0x0b, 0x00, 0x03, 0x0d,
      0x08, 0x0f, 0x04, 0x02,
    ];
    return sBoxTable[num];
  }
  inverse_sBox(num) {
    const sBoxTable = [
      0x09, 0x04, 0x0f, 0x0a, 0x0e, 0x01, 0x00, 0x06, 0x0c, 0x07, 0x03, 0x08,
      0x02, 0x0b, 0x05, 0x0d,
    ];
    return sBoxTable[num];
  }

  generateRoundKey(final = false) {
    const roundKey = new Uint16Array(this.key);
    for (let i = 0; i < 4; i++) {
      roundKey[i] = this.key[i];
    }
    if (!final) {
      this.subColumn(this.key, 4);

      const row0 = this.key[0];
      this.key[0] = this.clsh(this.key[0], 8) ^ this.key[1];
      this.key[1] = this.key[2];
      this.key[2] = this.key[3];
      this.key[3] = this.clsh(this.key[3], 12) ^ this.key[4];
      this.key[4] = row0;

      let lowerBits5 = this.key[0] & 0x0000001f;
      lowerBits5 ^= this.rc;
      this.key[0] = (this.key[0] & 0xffffffe0) | lowerBits5;
    }
    return roundKey;
  }

  addRoundKey(roundKey) {
    for (let i = 0; i < 4; i++) {
      this.cipherText[i] ^= roundKey[i];
    }
  }

  subColumn(state, cols = 16, sBox = this.sBox) {
    for (let i = 0; i < cols; i++) {
      let colVal = 0;
      const keyBits = [];
      for (let j = 0; j < 4; j++) {
        keyBits.push((state[j] >> i) & 1);
        colVal |= keyBits[j] << j;
      }
      colVal = sBox(colVal);
      for (let j = 0; j < 4; j++) {
        const colBit = (colVal >> j) & 1;
        state[j] ^= (colBit ^ keyBits[j]) << i;
      }
    }
  }

  shiftRow(inv = 0) {
    this.cipherText[1] = this.clsh(this.cipherText[1], Math.abs(inv - 1));
    this.cipherText[2] = this.clsh(this.cipherText[2], Math.abs(inv - 12));
    this.cipherText[3] = this.clsh(this.cipherText[3], Math.abs(inv - 13));
  }

  encrypt() {
    for (let i = 0; i < 25; i++) {
      this.generateRC(this.rc);
      const roundKey = this.generateRoundKey();
      this.addRoundKey(roundKey);
      this.subColumn(this.cipherText);
      this.shiftRow();
    }
    const roundKey = this.generateRoundKey(true);
    this.addRoundKey(roundKey);
  }

  saveInverseKeys() {
    const roundKeys = [];
    this.rc = 0;
    for (let i = 0; i < 25; i++) {
      this.generateRC(this.rc);
      roundKeys.push(this.generateRoundKey());
    }
    roundKeys.push(this.generateRoundKey(true));
    return roundKeys;
  }
  decrypt() {
    this.key = this.mainKey;
    const roundKeys = this.saveInverseKeys();
    for (let i = 25; i >= 1; i--) {
      const roundKey = roundKeys[i];
      this.addRoundKey(roundKey);
      this.shiftRow(16);
      this.subColumn(this.cipherText, 16, this.inverse_sBox);
    }
    const roundKey = roundKeys[0];
    this.addRoundKey(roundKey);
  }
}


const testCases = [
  {
    key: [0xffff, 0xffff, 0xffff, 0xffff, 0xaaaa],
    plaintext: [0xabca, 0x4611, 0xffff, 0x1234],
  },
  {
    key: [0xfffe, 0xffff, 0xffff, 0xffff, 0xbbbb],
    plaintext: [0xabca, 0x4611, 0xffff, 0x5678],
  },
  {
    key: [0xffff, 0xffff, 0xffff, 0xffff, 0xcccc],
    plaintext: [0xabcb, 0x4611, 0xffff, 0x9abc],
  },
  {
    key: [0xffff, 0xffff, 0xffff, 0xffff, 0xdddd],
    plaintext: [0xabca, 0x4611, 0xffff, 0xdef0],
  },
];

testCases.forEach((testCase) => {
  console.log("\nStart test case\n");
  const newRectangle = new Rectangle(testCase.plaintext, testCase.key);
  console.log("Plain Text: ");
  newRectangle.plainText.forEach((row) =>
    console.log(row.toString(16).padStart(4, "0"))
  );
  console.log("-----------------------");
  console.log("Cipher Text: ");
  newRectangle.encrypt();
  newRectangle.cipherText.forEach((row) =>
    console.log(row.toString(16).padStart(4, "0"))
  );
  console.log("-----------------------");
  console.log("Plain Text after decryption: ");
  newRectangle.decrypt();
  newRectangle.cipherText.forEach((row) =>
    console.log(row.toString(16).padStart(4, "0"))
  );
  console.log("\nEnd test case\n");
});