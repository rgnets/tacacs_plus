module TacacsPlus

# A class defining the standard TACACS+ packet header.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |major  | minor  |                |                |                |
#        |version| version|      type      |     seq_no     |   flags        |
#        +----------------+----------------+----------------+----------------+
#        |                                                                   |
#        |                            session_id                             |
#        +----------------+----------------+----------------+----------------+
#        |                                                                   |
#        |                              length                               |
#        +----------------+----------------+----------------+----------------+
#
# Required size =  12 bytes
#
class TacacsHeader #:nodoc: all

# MIXINS
    include TacacsPlus::Version
    include TacacsPlus::Type
    include TacacsPlus::SeqNo
    include TacacsPlus::Flags
    include TacacsPlus::SessionId
    include TacacsPlus::Length

#  CONSTANTS

    # header length    
    TACACS_HEADER_SIZE = 12

    # flags
    TAC_PLUS_UNENCRYPTED_FLAG = 0x01
    TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04

  
#==============================================================================#
# initialize()
#==============================================================================#

#===Synopsis
#Create a TACACS+ header object.
#
#===Usage
# header = TacacsPlus::TacacsHeader.new
# header = TacacsPlus::TacacsHeader.new(packed_header)
#
#===Arguments:
#* Byte-packed String representing a TACACS+ packet header. - Optional
#
    def initialize(header=nil)      
        if (header)
            if (!header.kind_of?(String))
                raise ArgumentError, "Expected String, but #{header.class} provided."
            end
            
            if (header.length != 12)
                raise ArgumentError, "Provided String should be 12-bytes but was #{header.length}-bytes."
            end

            unpack_header(header)
        else        
            # set defaults
            reset!
        end
                
    end


#==============================================================================#
# flag_single_connection?()
#==============================================================================#

#Is the 'single_connection' flag set?
#
    def flag_single_connection?()
        return(true) if(@flags & TAC_PLUS_SINGLE_CONNECT_FLAG == TAC_PLUS_SINGLE_CONNECT_FLAG)
        return(false)
    end


#==============================================================================#
# flag_single_connection!()
#==============================================================================#

#Toggle the 'single_connection' flag.
#
    def flag_single_connection!
        if (!flag_single_connection?)
            @flags = @flags | TAC_PLUS_SINGLE_CONNECT_FLAG
        else
            @flags = @flags & (~TAC_PLUS_SINGLE_CONNECT_FLAG)
        end
        return(nil)
    end


#==============================================================================#
# flag_unencrypted?()
#==============================================================================#

#Is the 'unencrypted' flag set?
#
    def flag_unencrypted?()
        return(true) if(@flags & TAC_PLUS_UNENCRYPTED_FLAG == TAC_PLUS_UNENCRYPTED_FLAG)
        return(false)
    end

#==============================================================================#
# flag_unencrypted!()
#==============================================================================#

#Toggle the 'unencrypted' flag.
#
    def flag_unencrypted!
        if (!flag_unencrypted?)
            @flags = @flags | TAC_PLUS_UNENCRYPTED_FLAG
        else
            @flags = @flags & (~TAC_PLUS_UNENCRYPTED_FLAG)
        end
        return(nil)
    end

#==============================================================================#
# packed()
#==============================================================================#

# Return all fields as a single byte-packed String.
#
    def packed()
        header = self.version.chr + 
                 @type.chr + 
                 @seq_no.chr + 
                 @flags.chr + 
                 TacacsPlus.pack_int_net(@session_id,4) + 
                 TacacsPlus.pack_int_net(@length,4)
        return(header)
    end

#==============================================================================#
# print()
#==============================================================================#

# Return a human readable printout of all fields.
#
    def print()
        header = "--- TacacsHeader ---\n" +
                 "[Major Version] #{xlate_major_version}\n" +
                 "[Minor Version] #{xlate_minor_version}\n" + 
                 "[Type] #{xlate_type}\n" + 
                 "[Sequence Number] #{@seq_no}\n" + 
                 "[Flags] #{xlate_flags}\n" + 
                 "[Session ID] #{@session_id}\n" + 
                 "[Length] #{@length}"
        return(header)
    end

#==============================================================================#
# reset!()
#==============================================================================#

# Reset all fields to default.
#
    def reset!()
        @major_version = TAC_PLUS_MAJOR_VER
        @minor_version = TAC_PLUS_MINOR_VER_DEFAULT
        @type = 0
        @seq_no = 1
        @flags = 0
        @session_id = 0
        @length = 0
        return(nil)
    end

#==============================================================================#
# xlate_flags()
#==============================================================================#

# Translate '' field into human readable form.
#
    def xlate_flags()
        flags = []
        flags.push('Single Connection') if (flag_single_connection?)
        flags.push('Unencrypted') if (flag_unencrypted?)
        return(flags.join(', ')) if (flags.length != 0)
        return("None")
    end


# PRIVATE INSTANT METHODS
private

#==============================================================================#
# unpack_header()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
# - Arguments:
#   * String
#
# - Returns:
#   * nil
#
    def unpack_header(header)
       # fixed fields
        self.version = header.slice!(0)
        self.type = header.slice!(0)
        self.seq_no = header.slice!(0)
        self.flags = header.slice!(0)
        self.session_id = header.slice!(0..3)
        self.length = header.slice!(0..3)
        return(nil)
    end
    
end # class TacacsHeader

end # module TacacsPlus

__END__
