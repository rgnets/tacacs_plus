module TacacsPlus

# A generic class for all TACACS+ Authentication messages.
class Authorization < TacacsBody #:nodoc:

# Is this an Authorization Request message?
    def authorization_request?
        return true if (self.kind_of?(AuthorizationRequest))
        return false
    end

# Is this an Authorization Response message?
    def authorization_response?
        return true if (self.kind_of?(AuthorizationResponse))
        return false
    end
end


# A class defining the standard TACACS+ Athorization Request body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |  authen_method |    priv_lvl    |  authen_type   | authen_service |
#        +----------------+----------------+----------------+----------------+
#        |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
#        +----------------+----------------+----------------+----------------+
#        |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
#        +----------------+----------------+----------------+----------------+
#        |   user ...
#        +----------------+----------------+----------------+----------------+
#        |   port ...
#        +----------------+----------------+----------------+----------------+
#        |   rem_addr ...
#        +----------------+----------------+----------------+----------------+
#        |   arg 1 ...
#        +----------------+----------------+----------------+----------------+
#        |   arg 2 ...
#        +----------------+----------------+----------------+----------------+
#        |   ...
#        +----------------+----------------+----------------+----------------+
#        |   arg N ...
#        +----------------+----------------+----------------+----------------+
#
# Max size = 66309 bytes
# Min size = 8 bytes
#
class AuthorizationRequest < Authorization #:nodoc: all

# MIXINS
    include TacacsPlus::AuthenMethod
    include TacacsPlus::PrivLvl
    include TacacsPlus::AuthenType
    include TacacsPlus::Service
    include TacacsPlus::User
    include TacacsPlus::Port
    include TacacsPlus::RemAddr
    include TacacsPlus::Args

#==============================================================================#
# packed()
#==============================================================================#

# Pack all fields together as a single byte-packed String.
#
    def packed()
        body = @authen_method.chr +
               @priv_lvl.chr + 
               @authen_type.chr +
               @service.chr +
               @user_len.chr +
               @port_len.chr +
               @rem_addr_len.chr +
               @arg_cnt.chr

        body << @arg_lens.pack('C*') if (@arg_lens && @arg_lens.length != 0)
        body << @user if (@user)
        body << @port if (@port)
        body << @rem_addr if (@rem_addr)
        body << @args.join if (@args && @args.length != 0)

        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

# Return a String printout of all fields in YAML format.
#
    def print()
        body = "--- AuthorizationRequest ---\n" +
               "[Authentication Method] #{xlate_authen_method}\n" +
               "[Privilege Level] #{@priv_lvl}\n" +
               "[Authentication Type] #{xlate_authen_type}\n" +
               "[Authentication Service] #{xlate_service}\n" +
               "[User Length] #{@user_len}\n" +
               "[Port Length] #{@port_len}\n" +
               "[Remote Address Length] #{@rem_addr_len}\n" + 
               "[Argument Count] #{@arg_cnt}"
        
        body << "\n[Argument Length(s)] #{@arg_lens.join(',')}" if (@arg_lens && @arg_lens.length != 0)
        body << "\n[User] #{@user.gsub(/\n/,"\n" + " " * 7)}" if (@user)
        body << "\n[Port] #{@port.gsub(/\n/,"\n" + " " * 7)}" if (@port)
        body << "\n[Remote Address] #{@rem_addr.gsub(/\n/,"\n" + " " * 17)}" if (@rem_addr)
        body << "\n[Argument(s)] #{@args.join(',')}" if (@args && @args.length != 0)

        return(body)
    end

#==============================================================================#
# reset!()
#==============================================================================#

# Reset all fields to default.
#
    def reset!()
        # fixed-length fields
        @authen_method = 0
        @priv_lvl = 0
        @authen_type = 0
        @service = 0
        @user_len = 0
        @port_len = 0
        @rem_addr_len = 0
        @arg_cnt = 0
       
        # variable-length fields
        @arg_lens = []
        @user = nil
        @port = nil
        @rem_addr = nil
        @args = []        

        return(nil)
    end

#==============================================================================#
# set_len!()
#==============================================================================#

# Set all length fields based on their matching data field.
#
    def set_len!()
        @arg_cnt = @args.length
        @user_len = @user.length if (@user)
        @port_len = @port.length if (@port)
        @rem_addr_len = @rem_addr.length if (@rem_addr)
        if (@arg_cnt != 0)
            @arg_lens = []
            @args.each {|x| @arg_lens.push(x.length)}
        end 
        return(nil)
    end



#PRIVATE INSTANCE METHODS
private

#==============================================================================#
# max_size()
#==============================================================================#

# max packet length
    def max_size()
       AUTHORIZATION_REQUEST_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        AUTHORIZATION_REQUEST_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
    def unpack_body(body)
        # fixed fields
        self.authen_method = body.slice!(0)
        self.priv_lvl = body.slice!(0)
        self.authen_type = body.slice!(0)
        self.authen_service = body.slice!(0)
        self.user_len = body.slice!(0)
        self.port_len = body.slice!(0)
        self.rem_addr_len = body.slice!(0)
        self.arg_cnt = body.slice!(0)

        # variable fields
        @arg_lens = (body.slice!(0..(@arg_cnt - 1))).unpack('C*') if (@arg_cnt != 0)
        @user = body.slice!(0..(@user_len - 1)) if (@user_len != 0)
        @port = body.slice!(0..(@port_len - 1)) if (@port_len != 0)
        @rem_addr = body.slice!(0..(@rem_addr_len - 1)) if (@rem_addr_len != 0)

        if (self.arg_cnt != 0)
            @args = []
            @arg_lens.each do |x|
                if (x > 0)
                    @args.push( body.slice!( 0..(x - 1) ) )
                else
                    @args.push('')
                end
            end
        end

        return(nil)
    end


end # class AuthorizationRequest





# A class defining the standard TACACS+ Athorization Response body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |    status      |     arg_cnt    |         server_msg len          |
#        +----------------+----------------+----------------+----------------+
#        +            data len             |    arg 1 len   |    arg 2 len   |
#        +----------------+----------------+----------------+----------------+
#        |      ...       |   arg N len    |         server_msg ...
#        +----------------+----------------+----------------+----------------+
#        |   data ...
#        +----------------+----------------+----------------+----------------+
#        |   arg 1 ...
#        +----------------+----------------+----------------+----------------+
#        |   arg 2 ...
#        +----------------+----------------+----------------+----------------+
#        |   ...
#        +----------------+----------------+----------------+----------------+
#        |   arg N ...
#        +----------------+----------------+----------------+----------------+
#
# Max size = 196612 bytes
# Min size = 6 bytes
#
class AuthorizationResponse < Authorization #:nodoc: all

# MIXINS
    include TacacsPlus::Status
    include TacacsPlus::Args
    include TacacsPlus::ServerMsg
    include TacacsPlus::Data

# CONSTANTS

    # status
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01
    TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
    TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10
    TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11
    TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21
    STATUS_XLATES = {TAC_PLUS_AUTHOR_STATUS_PASS_ADD => "Pass Add",
                     TAC_PLUS_AUTHOR_STATUS_PASS_REPL => "Pass Replace",
                     TAC_PLUS_AUTHOR_STATUS_FAIL => "Fail",
                     TAC_PLUS_AUTHOR_STATUS_ERROR => "Error",
                     TAC_PLUS_AUTHOR_STATUS_FOLLOW => "Follow"}

#==============================================================================#
# packed()
#==============================================================================#

# Pack all fields together as a single byte-packed String.
#
    def packed()
        body = @status.chr + 
               @arg_cnt.chr +
               TacacsPlus.pack_int_net(@server_msg_len,2) +
               TacacsPlus.pack_int_net(@data_len,data_len_bytes)
        
        body << @arg_lens.pack('C*') if (@arg_lens && @arg_lens.length != 0)
        body << @server_msg if (@server_msg)
        body << @data if (@data)
        body << @args.join if (@args && @args.length != 0)
       
        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

# Return a String printout of all fields in YAML format.
#
    def print()
        body = "--- AuthorizationResponse ---\n" +
               "[Status] #{xlate_status}\n" + 
               "[Argument Count] #{@arg_cnt}\n" + 
               "[Server Message Length] #{@server_msg_len}\n" + 
               "[Data Length] #{@data_len}"
        
        body << "\n[Argument Lengths] #{@arg_lens.join(',')}" if (@arg_lens && @arg_lens.length != 0)
        body << "\n[Server Message] #{@server_msg.gsub(/\n/,"\n" + " " * 17)}" if (@server_msg)
        body << "\n[Data] #{@data.gsub(/\n/,"\n" + " " * 7)}" if (@data)
        body << "\n[Arguments] #{@args.join(',')}" if (@args && @args.length != 0)
        return(body)
    end

#==============================================================================#
# reset!()
#==============================================================================#

# Reset all fields to default.
#
    def reset!()
        # fixed-length fields
        @status = 0
        @arg_cnt = 0
        @server_msg_len = 0
        @data_len = 0
       
        # variable-length fields
        @arg_lens = []
        @server_msg = nil
        @data = nil
        @args = []

        return(nil)
    end

#==============================================================================#
# set_len!()
#==============================================================================#

# Set all length fields based on their matching data field.
#
    def set_len!()
        @arg_cnt = @args.length
        @server_msg_len = @server_msg.length if (@server_msg)
        @data_len = @data.length if (@data)
        if (@arg_cnt != 0)
            @arg_lens = []
            @args.each {|x| @arg_lens.push(x.length)}
        end 
        return(nil)
    end

#==============================================================================#
# status_passadd?()
#==============================================================================#

#Is the 'status' field set to 'passadd'?
#
    def status_passadd?()
        return true if (@status == TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        return false
    end   

#==============================================================================#
# status_passadd!()
#==============================================================================#

#Set the 'status' field to 'passadd'.
#
    def status_passadd!()
        @status = TAC_PLUS_AUTHOR_STATUS_PASS_ADD
    end   

#==============================================================================#
# status_passrepl?()
#==============================================================================#

#Is the 'status' field set to 'passrepl'?
#
    def status_passrepl?()
        return true if (@status == TAC_PLUS_AUTHOR_STATUS_PASS_REPL)
        return false
    end   

#==============================================================================#
# status_passrepl!()
#==============================================================================#

#Set the 'status' field to 'passrepl'.
#
    def status_passrepl!()
        @status = TAC_PLUS_AUTHOR_STATUS_PASS_REPL
    end   

#==============================================================================#
# status_fail?()
#==============================================================================#

#Is the 'status' field set to 'fail'?
#
    def status_fail?()
        return true if (@status == TAC_PLUS_AUTHOR_STATUS_FAIL)
        return false
    end   

#==============================================================================#
# status_fail!()
#==============================================================================#

#Set the 'status' field to 'fail'.
#
    def status_fail!()
        @status = TAC_PLUS_AUTHOR_STATUS_FAIL
    end   

#==============================================================================#
# status_error?()
#==============================================================================#

#Is the 'status' field set to 'error'?
#
    def status_error?()
        return true if (@status == TAC_PLUS_AUTHOR_STATUS_ERROR)
        return false
    end   

#==============================================================================#
# status_error!()
#==============================================================================#

#Set the 'status' field to 'error'.
#
    def status_error!()
        @status = TAC_PLUS_AUTHOR_STATUS_ERROR
    end   

#==============================================================================#
# status_follow?()
#==============================================================================#

#Is the 'status' field set to 'follow'?
#
    def status_follow?()
        return true if (@status == TAC_PLUS_AUTHOR_STATUS_FOLLOW)
        return false
    end   

#==============================================================================#
# status_follow!()
#==============================================================================#

#Set the 'status' field to 'follow'.
#
    def status_follow!()
        @status = TAC_PLUS_AUTHOR_STATUS_FOLLOW
    end

#==============================================================================#
# xlate_status()
#==============================================================================#

# Translate 'status' field into human readable form.
#
    def xlate_status()
        return STATUS_XLATES[@status] if (STATUS_XLATES.has_key?(@status))
        return(@status.to_s)     
    end    
    

#PRIVATE INSTANCE METHODS
private

#==============================================================================#
# data_len_bytes()
#==============================================================================#

# the length of the data_len field in bytes
    def data_len_bytes()
        2
    end

#==============================================================================#
# max_size()
#==============================================================================#

# max packet length
    def max_size()
        AUTHORIZATION_RESPONSE_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        AUTHORIZATION_RESPONSE_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
    def unpack_body(body)
        # fixed fields
        self.status = body.slice!(0)
        self.arg_cnt = body.slice!(0)
        self.server_msg_len = body.slice!(0..1)
        self.data_len = body.slice!(0..1)

       
        # variable fields
        @arg_lens = (body.slice!(0..(@arg_cnt - 1))).unpack('C*') if (@arg_cnt != 0)
        @server_msg = body.slice!(0..(@server_msg_len - 1)) if (@server_msg_len != 0)
        @data = body.slice!(0..(@data_len - 1)) if (@data_len != 0)
        if (self.arg_cnt != 0)
            @args = []
            @arg_lens.each {|x| @args.push( body.slice!( 0..(x - 1) ) )}
        end 
   
        return(nil)
    end

end # class AuthorizationResponse



end # module TacacsPlus

__END__
