module TacacsPlus

# A generic class for the body of a TACACS+ packet.
class TacacsBody #:nodoc: all

#  CONSTANTS

    # body min and max sizes
    AUTHENTICATION_START_MIN_SIZE = 8
    AUTHENTICATION_START_MAX_SIZE = 1028
    AUTHENTICATION_REPLY_MIN_SIZE = 6
    AUTHENTICATION_REPLY_MAX_SIZE = 131076
    AUTHENTICATION_CONTINUE_MIN_SIZE = 5
    AUTHENTICATION_CONTINUE_MAX_SIZE = 131075
    AUTHORIZATION_REQUEST_MIN_SIZE = 8
    AUTHORIZATION_REQUEST_MAX_SIZE = 66309
    AUTHORIZATION_RESPONSE_MIN_SIZE = 6
    AUTHORIZATION_RESPONSE_MAX_SIZE = 196612
    ACCOUNTING_REQUEST_MIN_SIZE = 9
    ACCOUNTING_REQUEST_MAX_SIZE = 66310
    ACCOUNTING_REPLY_MIN_SIZE = 5
    ACCOUNTING_REPLY_MAX_SIZE = 131075

#==============================================================================#
# initialize()
#==============================================================================#

#===Synopsis
#Create one of the TACACS+ body objects (AthenticationStart, AthenticationContinue, AthenticationReply,
#AuthorizationRequest, AuthorizationResponse, AccountingRequest, AccountingReply)
#
#===Usage
# start = TacacsPlus::AuthenticationStart.new
# request = TacacsPlus::AuthorizationRequest.new
# reply = TacacsPlus::AccountingReply.new(packed_body)
#
#===Arguments:
#* Byte-packed String representing one of the TACACS+ packet body classes. - Optional
#
    def initialize(body=nil)
        if (body)
            if (!body.kind_of?(String))
                raise ArgumentError, "Expected String, but #{body.class} provided."
            end

            if (body.length > max_size)
                raise ArgumentError, "Provided String, of size (#{body.length}-bytes), exceeds " +
                                     "size limit of #{max_size}-bytes for a #{self.class} object."
            end

            if (body.length < min_size)
                raise ArgumentError, "Provided String, of size (#{body.length}-bytes), does " +
                                     "not meet the minimum size of #{min_size}-bytes required for a " +
                                     "#{self.class} object."
            end
            unpack_body(body)
        else
            # set defaults
            reset!
        end

    end

end # class TacacsBody

end # module TacacsPlus

__END__
