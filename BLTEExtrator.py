#! coding: utf8
import os, zlib, glob, urllib2
from hashlib import md5 as md5_builtin
from struct import unpack

class FileObject:
    def __init__(self, path):
        self.f = open(path, 'rb')

    def __del__(self):
        self.f.close()
        
    def read(self, bytes):
        return self.f.read(bytes)
        
    def tell(self):
        return self.f.tell()
        
    def seek(self, pos):
        self.f.seek(pos)
        
    def read_int32_LE(self):
        """
        rtype: int base 16
        """
        return int(hex(unpack('<i', self.f.read(4))[0]), 16)
        
    def read_int32_BE(self):
        """
        rtype: int base 16
        """
        return int(hex(unpack('>i', self.f.read(4))[0]), 16)
        
class BLTE:
    def __init__(self, input_path, hash_in_filename):
        """
        :param input_path      : input BLTE file path
        :param hash_in_filename: hash of this BLTE, usually filename
        """
        self.path = input_path
        self.hash = hash_in_filename
        
    def string_to_hex(self, string, delimiter=''):
        """Convert string 'poi' to hex string '706f69'
        :param string: input string
        :type  string: string
        :rtype       : string
        """
        return delimiter.join('{:02x}'.format(ord(c)) for c in string)
            
    def md5(self, s):
        """
        :rtype : string
        """
        return md5_builtin(s).hexdigest()

    def extract(self):
        input_path = self.path
        hash_in_filename = self.hash
        
        f = FileObject(input_path)
        if not hash_in_filename:
            hash_in_filename = os.path.basename(input_path)
        file_size = os.path.getsize(input_path)
        
        # magic check
        file_signature = f.read_int32_LE()
        if file_signature != 0x45544c42:
            raise Exception('Invalid file signature')

        header_size = f.read_int32_BE()
        
        # BLTE hash check
        temp_pos = f.tell()
        f.seek(0)
        if header_size > 0:
            blte_hash = self.md5(f.read(header_size))
        else:
            blte_hash = self.md5(f.read())
        if blte_hash != hash_in_filename:
            raise Exception('BLTE hash checksum mismatch')
        f.seek(temp_pos)
        
        # process ChunkInfo
        if header_size > 0:
            fcbytes = f.read(4)
            chunk_count = unpack('>i', chr(0)+fcbytes[1:])[0]

        # process ChunkInfoEntry
        chunks = []
        for i in xrange(chunk_count):
            chunk_info_entry = {}
            if header_size != 0:
                chunk_info_entry['compressed_size'] = f.read_int32_BE()
                chunk_info_entry['decompressed_size'] = f.read_int32_BE()
                chunk_info_entry['checksum'] = self.string_to_hex(f.read(16))
            else:
                chunk_info_entry['compressed_size'] = file_size - 8
                chunk_info_entry['decompressed_size'] = file_size - 8 - 1
                chunk_info_entry['checksum'] = None
            chunks.append(chunk_info_entry)
            
        # extract chunk/data
        for chunk in chunks:
            chunk['data'] = f.read(chunk['compressed_size'])
            if chunk['checksum'] and self.md5(chunk['data']) !=  chunk['checksum']:
                raise Exception('Chunk hash checksum mismatch')
            yield self.decode_chunk(chunk['data'])
        
    def decode_chunk(self, data):
        flag = self.string_to_hex(data[0])
        if flag == '45': # E, encrypted: one of salsa20, arc4, rc4
            raise Exception('One of Salsa20, ARC4, RC4, not implemented yet')
        elif flag == '46': # F, Recursively encoded BLTE data.
            raise Exception('Recursively encoded BLTE data, not implemented yet')
        elif flag == '4e': # N, Plain data
            return data[1:]
        elif flag == '5a': # Z, Zlib encoded data
            return zlib.decompress(data[1:])

def main():
    with open('tmp', 'wb+') as f:
        f.write(urllib2.urlopen('http://dist.blizzard.com.edgesuite.net/tpr/\
wow/data/2e/d8/2ed87af5044ed167e1fbc9d888ad3fdb').read())
    for decoded_chunk in BLTE('tmp', '2ed87af5044ed167e1fbc9d888ad3fdb').extract():
        print('%s %s' % (
            len(decoded_chunk),
            ''.join('{:02x}'.format(ord(c)) for c in decoded_chunk[:30])
        ))
    
if __name__ == '__main__':
    main()
