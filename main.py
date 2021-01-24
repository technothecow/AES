class Encryptor:
    SBOX = {'0': {'0': b'\x63', '1': b'\x7c', '2': b'\x77', '3': b'\x7b', '4': b'\xf2', '5': b'\x6b', '6': b'\x6f',
                  '7': b'\xc5', '8': b'\x30', '9': b'\x01', 'a': b'\x67', 'b': b'\x2b', 'c': b'\xfe', 'd': b'\xd7',
                  'e': b'\xab', 'f': b'\x76'},
            '1': {'0': b'\xca', '1': b'\x82', '2': b'\xc9', '3': b'\x7d', '4': b'\xfa', '5': b'\x59', '6': b'\x47',
                  '7': b'\xf0', '8': b'\xad', '9': b'\xd4', 'a': b'\xa2', 'b': b'\xaf', 'c': b'\x9c', 'd': b'\xa4',
                  'e': b'\x72', 'f': b'\xc0'},
            '2': {'0': b'\xb7', '1': b'\xfd', '2': b'\x93', '3': b'\x26', '4': b'\x36', '5': b'\x3f', '6': b'\xf7',
                  '7': b'\xcc', '8': b'\x34', '9': b'\xa5', 'a': b'\xe5', 'b': b'\xf1', 'c': b'\x71', 'd': b'\xd8',
                  'e': b'\x31', 'f': b'\x15'},
            '3': {'0': b'\x04', '1': b'\xc7', '2': b'\x23', '3': b'\xc3', '4': b'\x18', '5': b'\x96', '6': b'\x05',
                  '7': b'\x9a', '8': b'\x07', '9': b'\x12', 'a': b'\x80', 'b': b'\xe2', 'c': b'\xeb', 'd': b'\x27',
                  'e': b'\xb2', 'f': b'\x75'},
            '4': {'0': b'\x09', '1': b'\x83', '2': b'\x2c', '3': b'\x1a', '4': b'\x1b', '5': b'\x6e', '6': b'\x5a',
                  '7': b'\xa0', '8': b'\x52', '9': b'\x3b', 'a': b'\xd6', 'b': b'\xb3', 'c': b'\x29', 'd': b'\xe3',
                  'e': b'\x2f', 'f': b'\x84'},
            '5': {'0': b'\x53', '1': b'\xd1', '2': b'\x00', '3': b'\xed', '4': b'\x20', '5': b'\xfc', '6': b'\xb1',
                  '7': b'\x5b', '8': b'\x6a', '9': b'\xcb', 'a': b'\xbe', 'b': b'\x39', 'c': b'\x4a', 'd': b'\x4c',
                  'e': b'\x58', 'f': b'\xcf'},
            '6': {'0': b'\xd0', '1': b'\xef', '2': b'\xaa', '3': b'\xfb', '4': b'\x43', '5': b'\x4d', '6': b'\x33',
                  '7': b'\x85', '8': b'\x45', '9': b'\xf9', 'a': b'\x02', 'b': b'\x7f', 'c': b'\x50', 'd': b'\x3c',
                  'e': b'\x9f', 'f': b'\xa8'},
            '7': {'0': b'\x51', '1': b'\xa3', '2': b'\x40', '3': b'\x8f', '4': b'\x92', '5': b'\x9d', '6': b'\x38',
                  '7': b'\xf5', '8': b'\xbc', '9': b'\xb6', 'a': b'\xda', 'b': b'\x21', 'c': b'\x10', 'd': b'\xff',
                  'e': b'\xf3', 'f': b'\xd2'},
            '8': {'0': b'\xcd', '1': b'\x0c', '2': b'\x13', '3': b'\xec', '4': b'\x5f', '5': b'\x97', '6': b'\x44',
                  '7': b'\x17', '8': b'\xc4', '9': b'\xa7', 'a': b'\x7e', 'b': b'\x3d', 'c': b'\x64', 'd': b'\x5d',
                  'e': b'\x19', 'f': b'\x73'},
            '9': {'0': b'\x60', '1': b'\x81', '2': b'\x4f', '3': b'\xdc', '4': b'\x22', '5': b'\x2a', '6': b'\x90',
                  '7': b'\x88', '8': b'\x46', '9': b'\xee', 'a': b'\xb8', 'b': b'\x14', 'c': b'\xde', 'd': b'\x5e',
                  'e': b'\x0b', 'f': b'\xdb'},
            'a': {'0': b'\xe0', '1': b'\x32', '2': b'\x3a', '3': b'\x0a', '4': b'\x49', '5': b'\x06', '6': b'\x24',
                  '7': b'\x5c', '8': b'\xc2', '9': b'\xd3', 'a': b'\xac', 'b': b'\x62', 'c': b'\x91', 'd': b'\x95',
                  'e': b'\xe4', 'f': b'\x79'},
            'b': {'0': b'\xe7', '1': b'\xc8', '2': b'\x37', '3': b'\x6d', '4': b'\x8d', '5': b'\xd5', '6': b'\x4e',
                  '7': b'\xa9', '8': b'\x6c', '9': b'\x56', 'a': b'\xf4', 'b': b'\xea', 'c': b'\x65', 'd': b'\x7a',
                  'e': b'\xae', 'f': b'\x08'},
            'c': {'0': b'\xba', '1': b'\x78', '2': b'\x25', '3': b'\x2e', '4': b'\x1c', '5': b'\xa6', '6': b'\xb4',
                  '7': b'\xc6', '8': b'\xe8', '9': b'\xdd', 'a': b'\x74', 'b': b'\x1f', 'c': b'\x4b', 'd': b'\xbd',
                  'e': b'\x8b', 'f': b'\x8a'},
            'd': {'0': b'\x70', '1': b'\x3e', '2': b'\xb5', '3': b'\x66', '4': b'\x48', '5': b'\x03', '6': b'\xf6',
                  '7': b'\x0e', '8': b'\x61', '9': b'\x35', 'a': b'\x57', 'b': b'\xb9', 'c': b'\x86', 'd': b'\xc1',
                  'e': b'\x1d', 'f': b'\x9e'},
            'e': {'0': b'\xe1', '1': b'\xf8', '2': b'\x98', '3': b'\x11', '4': b'\x69', '5': b'\xd9', '6': b'\x8e',
                  '7': b'\x94', '8': b'\x9b', '9': b'\x1e', 'a': b'\x87', 'b': b'\xe9', 'c': b'\xce', 'd': b'\x55',
                  'e': b'\x28', 'f': b'\xdf'},
            'f': {'0': b'\x8c', '1': b'\xa1', '2': b'\x89', '3': b'\x0d', '4': b'\xbf', '5': b'\xe6', '6': b'\x42',
                  '7': b'\x68', '8': b'\x41', '9': b'\x99', 'a': b'\x2d', 'b': b'\x0f', 'c': b'\xb0', 'd': b'\x54',
                  'e': b'\xbb', 'f': b'\x16'}
            }

    RCON = [b'\x01\x00\x00\x00', b'\x02\x00\x00\x00', b'\x04\x00\x00\x00', b'\x08\x00\x00\x00', b'\x10\x00\x00\x00',
            b'\x20\x00\x00\x00', b'\x40\x00\x00\x00', b'\x80\x00\x00\x00', b'\x1B\x00\x00\x00', b'\x36\x00\x00\x00']

    def __init__(self, key: bytes = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'):
        self.key = key
        self.keys = list()
        self.generateKeys()
        self.current_text = None

    def encrypt_text(self, text: bytes) -> bytes:
        self.current_text = text
        self.addRoundKey()
        for i in range(9):
            self.subBytes()
            self.shiftRows()
            self.mixColumns()
            self.addRoundKey()
        self.subBytes()
        self.shiftRows()
        self.addRoundKey()
        return bytes(self.current_text)

    def subBytes(self):
        temp = self.current_text
        self.current_text = b''
        for i in range(len(self.current_text)):
            x, y = temp[i]
            self.current_text += self.SBOX[x][y]

    def shiftRows(self):
        temp_list = self.current_text
        self.current_text = b''
        self.current_text += temp_list[0]
        self.current_text += temp_list[5]
        self.current_text += temp_list[10]
        self.current_text += temp_list[15]
        self.current_text += temp_list[4]
        self.current_text += temp_list[9]
        self.current_text += temp_list[14]
        self.current_text += temp_list[3]
        self.current_text += temp_list[13]
        self.current_text += temp_list[2]
        self.current_text += temp_list[7]
        self.current_text += temp_list[12]
        self.current_text += temp_list[1]
        self.current_text += temp_list[6]
        self.current_text += temp_list[11]

    def generateKeys(self):
        def doSBOX(b):
            b = hex(b).lstrip('0x')
            b += '0' * (2 - len(b))
            x, y = b
            return self.SBOX[x][y]

        for i in range(10):
            formattedLastColumn = self.key[12 + 16 * i: 16 + 16 * i]
            formattedLastColumn = doSBOX(formattedLastColumn[1]) + doSBOX(formattedLastColumn[2]) + \
                                  doSBOX(formattedLastColumn[3]) + doSBOX(formattedLastColumn[0])

            columns = list()
            firstOfLastColumn = list()
            for j in range(4):
                firstOfLastColumn.append(self.key[i * 16:(i + 1) * 16 - i][j])
            firstColumn = list()
            for j in range(4):
                firstColumn.append(firstOfLastColumn[j] ^ formattedLastColumn[j] ^ self.RCON[i][j])

            columns.append(firstColumn.copy())

            for j in range(1, 4):
                columns.append(
                    [a ^ b for (a, b) in zip(self.key[i * 16:(i + 1) * 16][4 * j:8 * j], columns[j - 1])].copy())

            for j in columns:
                self.key += bytes(j)

    def addRoundKey(self):
        pass
