=begin rdoc
 Copyright (c) 2006 Dustin Spinhirne -  
 Licensed under the same terms as Ruby, No Warranty is provided.
=end

require 'time'
require 'digest/md5'
require 'socket'
require 'logger'
require 'yaml'
require 'digest/sha1'
require 'rubygems'
require 'netaddr'
gem 'netaddr', '>= 1.4.0'

require File.join(File.dirname(__FILE__), 'tacacs_socket.rb')
require File.join(File.dirname(__FILE__), 'client.rb')
require File.join(File.dirname(__FILE__), 'server.rb')
require File.join(File.dirname(__FILE__), 'tacacs_fields.rb')
require File.join(File.dirname(__FILE__), 'tacacs_header.rb')
require File.join(File.dirname(__FILE__), 'tacacs_body.rb')
require File.join(File.dirname(__FILE__), 'tacacs_authentication.rb')
require File.join(File.dirname(__FILE__), 'tacacs_authorization.rb')
require File.join(File.dirname(__FILE__), 'tacacs_accounting.rb')

module TacacsPlus

# PUBLIC CLASSES

# subclass logger so that i can control the output format
class ServerLogger < Logger #:nodoc:
  def delimiter=(val)
    @delimiter = val
  end

  def format_message(severity, timestamp, progname, msg)
    levels = {'DEBUG' => 0, 'INFO' => 1, 'WARN' => 2, 'ERROR' => 3, 'FATAL' => 4, 'UNKNOWN' => 5}
    "timestamp=#{timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")}#{@delimiter}level=#{levels[severity]}#{@delimiter}#{msg}\n"
  end
end

# Used to signal a TacacsPlus::Server to reinitialize its logger
class LoggerInit < StandardError #:nodoc:
end

# Used to signal a TacacsPlus::Server to cease running
class StopServer < StandardError #:nodoc:
end

# Raised if connection to client/server times out during communication
class TimeoutError < StandardError #:nodoc:
end

# Raised if error on packet decode
class DecodeError < StandardError #:nodoc:
end

# Raised if error on packet encode
class EncodeError < StandardError #:nodoc:
end

# TestIO
#
# Used for offline client/server testing.
class TestIO #:nodoc:
    attr_reader :read_data, :write_data

    def initialize(read_data)
        @read_data = read_data
        @write_data = []
        @read_pos = 0
    end

    def close
    end

    def closed?
        return(false)
    end

    def read()
        ret = nil
        if (@read_data.size > @read_pos)
            ret = @read_data[@read_pos]
            @read_pos += 1
        end
        return(ret)
    end

    # write to output
    def write(str)
        @write_data.push(str)
    end

end

# TestLogger
#
# Used for offline client/server testing.
class TestLogger < Logger #:nodoc:
    attr_reader :messages

    def initialize()
        @messages = []
    end

    def fatal(msg)
        @messages.push(msg)
    end

    def error(msg)
        @messages.push(msg)
    end

    def warn(msg)
        @messages.push(msg)
    end

    def info(msg)
        @messages.push(msg)
    end

    def debug(msg)
        @messages.push(msg)
    end

    def close
    end
end


# PUBLIC METHODS

#==============================================================================#
# decode_packet()
#==============================================================================#

#===Synopsis
#Given a byte-packed String representing an entire TACACS Plus packet 
#(header & body), decode it into a TacacsHeader and TacacsBody.
#
#===Usage
# decoded = TacacsPlus.decode_packet(packet)
#
#===Arguments:
#* String
#* Encryption key - String (Optional if unencrypted)
#
#===Returns:
#* PacketStruct
#
    def decode_packet(header,body,key=nil) #:nodoc:

        raise DecodeError, "Expected TacacsHeader for header, but #{header.class} provided." if (!header.kind_of?(TacacsPlus::TacacsHeader))
        raise DecodeError, "Expected String for body, but #{body.class} provided." if (!body.kind_of?(String))
        raise DecodeError, "Expected String for key, but #{key.class} provided." if (key && !key.kind_of?(String))

        raise DecodeError, "Packet header 'length' field (#{header.length}) does not match " +
              "actual body length (#{body.length})." if (body.length != header.length)

        # decrypt if needed
        if (!header.flag_unencrypted?)
            # decrypt
            raise DecodeError, "Encryption flag set in TacacsHeader, but no encryption key provided for decryption." if (!key)
            body = encrypt_decrypt(header,body,key)
        end

        # make TacacsBody. the seq_no is used to determine what type of
        # body to create.
        if (header.type_authorization?)
            if ( (header.seq_no & 1) == 1) # if odd seq_no
                body = TacacsPlus::AuthorizationRequest.new(body)
            else (header.seq_no ) # if even seq_no
                body = TacacsPlus::AuthorizationResponse.new(body)
            end

        elsif (header.type_authentication?)
            if (header.seq_no == 1)
                body = TacacsPlus::AuthenticationStart.new(body)
            elsif ( (header.seq_no & 1) == 1) # if odd seq_no
                body = TacacsPlus::AuthenticationContinue.new(body)
            else (header.seq_no ) # if even seq_no
                body = TacacsPlus::AuthenticationReply.new(body)
            end

        elsif (header.type_accounting?)
            if ( (header.seq_no & 1) == 1) # if odd seq_no
                body = TacacsPlus::AccountingRequest.new(body)
            else (header.seq_no ) # if even seq_no
                body = TacacsPlus::AccountingReply.new(body)
            end

        else
            raise DecodeError, "Unrecognized or unsupported TacacsBody defined by header 'type' field (#{header.type})."
        end

        return(PacketStruct.new(header, body))
    end
    module_function :decode_packet


#==============================================================================#
# encode_packet()
#==============================================================================#

#===Synopsis
#Given a TacacsHeader and TacacsBody, combine them into a single byte-packed
#string representing a complete TACACS Plus packet.
#
#===Usage
# packet = TacacsPlus.encode_packet(header, body, key)
#
#===Arguments:
#* PacketStruct
#* Encryption key - String (Optional if unencrypted)
#
#===Returns:
#* String
#
    def encode_packet(packet,key=nil) #:nodoc:
        raise EncodeError, "Expected PacketStruct for packet, but #{packet.class} provided." if (!packet.kind_of?(PacketStruct))
        raise EncodeError, "Expected TacacsHeader for packet.header, but #{packet.header.class} provided." if (!packet.header.kind_of?(TacacsHeader))
        raise EncodeError, "Expected TacacsBody for packet.body, but #{packet.body.class} provided." if (!packet.body.kind_of?(TacacsBody))
        raise EncodeError, "Expected String for key, but #{key.class} provided." if (key && !key.kind_of?(String))  

        packet.body = packet.body.packed

        # encrypt if needed
        if (!packet.header.flag_unencrypted?)
            raise EncodeError, "Encryption flag set in TacacsHeader, but no encryption key provided." if (!key)
            pkt = packet.header.packed + encrypt_decrypt(packet.header,packet.body,key)
        else
            pkt = packet.header.packed + packet.body
        end
        return(pkt)
    end
    module_function :encode_packet

#==============================================================================#
# validate_avpair()
#==============================================================================#

#===Synopsis
#Validate an AV-Pair String.
#
#===Usage
# avpair = TacacsPlus.validate_avpair('cmd=show')
#
#===Arguments:
#* String 
#
#===Returns:
#* Hash with the following keys:
#    :attribute - attribute portion of the avpair
#    :value - value portion of the avpair
#    :mandatory - is this a mandatory attr?
#
    def validate_avpair(avpair) #:nodoc:
        mandatory = true
        attribute = ''
        value = ''

        if(avpair.kind_of?(String))
            raise ArgumentError, "AVPairs must be 255-bytes or less, but was #{avpair.length}." if (avpair.length > 255)

            # split up into a-v based on * or = 
            if (avpair =~ /\=/)
                attribute,value = avpair.split('=',2)
            elsif (avpair =~ /\*/)
                mandatory = false
                attribute,value = avpair.split('*',2)
            elsif (avpair == '')
                attribute,value = ['','']
            else
                raise ArgumentError, "Improperly formed AVPair String '#{avpair}'."
            end

        else
            raise ArgumentError, "Expected String, but #{avpair.class} provided." 
        end

        return({:attribute => attribute, :value => value, :mandatory => mandatory})
    end
    module_function :validate_avpair

#==============================================================================#
# structs()
#==============================================================================#

#Struct object for holding a complete TACACS+ packet.
PacketStruct = Struct.new(:header, :body)





# PRIVATE METHODS
private

#==============================================================================#
# encrypt_decrypt()
#==============================================================================#

# Encrypt/decrypt a given TacacsBody
#
# - Arguments:
#   * TacacsHeader
#   * Packed TacacsBody or an encrypted String
#   * Encryption key
#
# - Returns:
#   * String
#
    def encrypt_decrypt(header,body,key)
	body_length = body.length

        # create first hash for pseudo pad from header fields & key
        unhashed = TacacsPlus.pack_int_net(header.session_id,4) +
                   key + 
                   header.version.chr +
                   header.seq_no.chr
        hashed = Digest::MD5.digest(unhashed)

        # make our initial pad from hashed.
        pad = hashed

        if (pad.length < body_length)
            # remake hash, appending it to pad until pad >= header.length
            while (1)
                hashed = Digest::MD5.digest(unhashed + hashed)
                pad << hashed
                break if (pad.length >=  body_length)
            end
        end

        # truncate pad to the length specified in header.length and unpack
        pad = pad[0..( body_length - 1)]
        pad = pad.unpack('C*') 

        # encrypt/decrypt each byte of TacacsBody with xor to 
        # to each byte of pseudo pad
        pkt_body = []
        body.unpack('C*').each do |x|
            pkt_body.push(x ^ pad.shift)
        end
        body = pkt_body.pack('C*')

        return(body)
    end
    module_function :encrypt_decrypt

#==============================================================================#
# pack_int_net()
#==============================================================================#

# Given an Integer, return it as a byte-packed String (network order).
#
# - Arguments:
#   * Integer to pack
#   * number of bytes to return
#
# - Returns:
#   * String
#
    def pack_int_net(number,size)
        str = ''
        size -= 1 if (size > 0)
        size.downto(0) do |x|
            str << ((number & (0xff << (8*x))) >> (8*x)).chr
        end
        return(str)
    end
    module_function :pack_int_net

#==============================================================================#
# validate_args()
#==============================================================================#

# validate options hash 
#
def validate_args(to_validate,known_args)
    to_validate.each do |x|
        raise ArgumentError, "Unrecognized argument '#{x}'. Valid arguments are " +
                             "#{known_args.join(', ')}" if (!known_args.include?(x))
    end
end 
module_function :validate_args  

end # module TacacsPlus


__END__
