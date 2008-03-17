module TacacsPlus

# A generic class for all TACACS+ Authentication messages.
class Authentication < TacacsBody #:nodoc:

# Is this an Authentication Continue message?
    def authentication_continue?
        return true if (self.kind_of?(AuthenticationContinue))
        return false
    end

# Is this an Authentication Reply message?
    def authentication_reply?
        return true if (self.kind_of?(AuthenticationReply))
        return false
    end

# Is this an Authentication Start message?
    def authentication_start?
        return true if (self.kind_of?(AuthenticationStart))
        return false
    end
end


# A class defining the standard TACACS+ Athentication Start body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |    action      |    priv_lvl    |  authen_type   |     service    |
#        +----------------+----------------+----------------+----------------+
#        |    user len    |    port len    |  rem_addr len  |    data len    |
#        +----------------+----------------+----------------+----------------+
#            user ...
#        +----------------+----------------+----------------+----------------+
#        |    port ...
#        +----------------+----------------+----------------+----------------+
#        |    rem_addr ...
#        ----------------+----------------+----------------+----------------+
#        |    data...
#        +----------------+----------------+----------------+----------------+
#
# Max size = 1028 bytes
# Min size = 8 bytes
#
class AuthenticationStart < Authentication #:nodoc: all

# MIXINS
    include TacacsPlus::Action
    include TacacsPlus::PrivLvl
    include TacacsPlus::AuthenType
    include TacacsPlus::Service
    include TacacsPlus::User
    include TacacsPlus::Port
    include TacacsPlus::RemAddr
    include TacacsPlus::Data

#==============================================================================#
# packed()
#==============================================================================#

#Return all fields as a single byte-packed String.
#
    def packed()
        body = @action.chr + 
               @priv_lvl.chr + 
               @authen_type.chr + 
               @service.chr + 
               @user_len.chr + 
               @port_len.chr + 
               @rem_addr_len.chr + 
               @data_len.chr

        body << @user if (@user)
        body << @port if (@port)
        body << @rem_addr if (@rem_addr)
        body << @data if (@data)
        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

#Return a human readable printout of all fields.
#
    def print()
        body = "--- AuthenticationStart ---\n" +
               "[Action] #{xlate_action}\n" + 
               "[Privilege Level] #{@priv_lvl}\n" + 
               "[Authentication Type] #{xlate_authen_type}\n" + 
               "[Service] #{xlate_service}\n" + 
               "[User Length] #{@user_len}\n" + 
               "[Port Length] #{@port_len}\n" + 
               "[Remote Addr Length] #{@rem_addr_len}\n" + 
               "[Data Length] #{@data_len}"

        body << "\n[User] #{@user.gsub(/\n/,"\n" + " " * 7)}" if (@user)
        body << "\n[Port] #{@port.gsub(/\n/,"\n" + " " * 7)}" if (@port)
        body << "\n[Remote Addr] #{@rem_addr.gsub(/\n/,"\n" + " " * 14)}" if (@rem_addr)
        body << "\n[Data] #{@data.gsub(/\n/,"\n" + " " * 7)}" if (@data)
        return(body)
    end

#==============================================================================#
# reset!()
#==============================================================================#

#Reset all fields to default.
#
    def reset!()
        # fixed-length fields
        @action = 0
        @priv_lvl = 0
        @authen_type = 0
        @service = 0
        @user_len = 0
        @port_len = 0
        @rem_addr_len = 0
        @data_len = 0

        # variable-length fields
        @user = nil
        @port = nil
        @rem_addr = nil
        @data = nil
        return(nil)
    end

#==============================================================================#
# set_len!()
#==============================================================================#

#Set all length fields based on their matching data field.
#
    def set_len!()
        @user_len = @user.length if (@user)
        @port_len = @port.length if (@port)
        @rem_addr_len = @rem_addr.length if (@rem_addr)
        @data_len = @data.length if (@data) 
        return(nil)
    end



#PRIVATE INSTANCE METHODS
private

#==============================================================================#
# data_len_bytes()
#==============================================================================#

# the length of the data_len field in bytes
    def data_len_bytes()
        1
    end

#==============================================================================#
# max_size()
#==============================================================================#

# max packet length
    def max_size()
        AUTHENTICATION_START_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        AUTHENTICATION_START_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
#===Arguments
#* String
#
#===Returns
#* nil
#
    def unpack_body(body)
       # fixed fields
       self.action = body.slice!(0)
       self.priv_lvl = body.slice!(0)
       self.authen_type = body.slice!(0)
       self.service = body.slice!(0)
       self.user_len = body.slice!(0)
       self.port_len = body.slice!(0)
       self.rem_addr_len = body.slice!(0)
       self.data_len = body.slice!(0)
       
       # variable fields
       self.user = body.slice!(0..(@user_len - 1)) if (@user_len != 0)
       self.port = body.slice!(0..(@port_len - 1)) if (@port_len != 0)
       self.rem_addr = body.slice!(0..(@rem_addr_len - 1)) if (@rem_addr_len != 0)
       self.data = body.slice!(0..(@data_len - 1)) if (@data_len != 0)   
        return(nil)
    end

    
end # class AuthenticationStart





# A class defining the standard TACACS+ Athentication Reply body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |     status     |      flags     |        server_msg len           |
#        +----------------+----------------+----------------+----------------+
#        |           data len              |        server_msg ...
#        +----------------+----------------+----------------+----------------+
#        |           data ...
#        +----------------+----------------+
#
# Max size = 131076 bytes
# Min size = 6 bytes
#
class AuthenticationReply < Authentication #:nodoc: all

# MIXINS
    include TacacsPlus::Status
    include TacacsPlus::Flags
    include TacacsPlus::ServerMsg
    include TacacsPlus::Data

# CONSTANTS

    # flags
    TAC_PLUS_REPLY_FLAG_NOECHO = 0x01
    
    # status 
    TAC_PLUS_AUTHEN_STATUS_PASS = 0x01
    TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02
    TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
    TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
    TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
    TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
    TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07
    TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21
    STATUS_XLATES = {TAC_PLUS_AUTHEN_STATUS_PASS => "Pass",
                     TAC_PLUS_AUTHEN_STATUS_FAIL => "Fail",
                     TAC_PLUS_AUTHEN_STATUS_GETDATA => "Get Data",
                     TAC_PLUS_AUTHEN_STATUS_GETUSER => "Get User",
                     TAC_PLUS_AUTHEN_STATUS_GETPASS => "Get Password",
                     TAC_PLUS_AUTHEN_STATUS_RESTART => "Restart",
                     TAC_PLUS_AUTHEN_STATUS_ERROR => "Error",
                     TAC_PLUS_AUTHEN_STATUS_FOLLOW => "Follow"}

#==============================================================================#
# flag_noecho?()
#==============================================================================#

#Is the 'noecho' flag set?
#
    def flag_noecho?()
        return(true) if(@flags & TAC_PLUS_REPLY_FLAG_NOECHO == TAC_PLUS_REPLY_FLAG_NOECHO)
        return(false)
    end   

#==============================================================================#
# flag_noecho!()
#==============================================================================#

#Toggle the 'noecho' flag.
#
    def flag_noecho!
        if (!flag_noecho?)
            @flags = @flags | TAC_PLUS_REPLY_FLAG_NOECHO
        else
            @flags = @flags & (~TAC_PLUS_REPLY_FLAG_NOECHO)
        end
        return(nil)
    end

#==============================================================================#
# packed()
#==============================================================================#

#Pack all fields together as a single byte-packed String.
#
    def packed()
        body = @status.chr + 
               @flags.chr + 
               TacacsPlus.pack_int_net(@server_msg_len,2) + 
               TacacsPlus.pack_int_net(@data_len,2) 
        
        body << @server_msg if (@server_msg)
        body << @data if (@data) 
        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

#Return a human readable printout of all fields.
#
    def print()
        body = "--- AuthenticationReply ---\n" +
               "[Status] #{xlate_status}\n" + 
               "[Flags] #{xlate_flags}\n" + 
               "[Server_msg_len] #{@server_msg_len}\n" + 
               "[Data_len] #{@data_len}" 
        
        body << "\n[Server Message] #{@server_msg.gsub(/\n/,"\n" + " " * 17)}" if (@server_msg)
        body << "\n[Data] #{@data.gsub(/\n/,"\n" + " " * 7)}" if (@data) 
        return(body)
    end
    


#==============================================================================#
# reset!()
#==============================================================================#

#Reset all fields to default.
#
    def reset!()
        # fixed-length fields
        @status = 0
        @flags = 0
        @server_msg_len = 0
        @data_len = 0       
       
        # variable-length fields
        @server_msg = nil
        @data = nil
        
        return(nil)
    end
 
#==============================================================================#
# set_len!()
#==============================================================================#

#Set all length fields based on their matching data field.
#
    def set_len!()
        @server_msg_len = @server_msg.length if (@server_msg)
        @data_len = @data.length if (@data) 
        return(nil)
    end

#==============================================================================#
# status_error?()
#==============================================================================#

#Is the 'status' field set to 'error'?
#
    def status_error?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_ERROR)
        return false
    end   

#==============================================================================#
# status_error!()
#==============================================================================#

#Set the 'status' field to 'error'.
#
    def status_error!()
        @status = TAC_PLUS_AUTHEN_STATUS_ERROR
    end   

#==============================================================================#
# status_fail?()
#==============================================================================#

#Is the 'status' field set to 'fail'?
#
    def status_fail?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_FAIL)
        return false
    end   

#==============================================================================#
# status_fail!()
#==============================================================================#

#Set the 'status' field to 'fail'.
#
    def status_fail!()
        @status = TAC_PLUS_AUTHEN_STATUS_FAIL
    end   

#==============================================================================#
# status_follow?()
#==============================================================================#

#Is the 'status' field set to 'follow'?
#
    def status_follow?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_FOLLOW)
        return false
    end   

#==============================================================================#
# status_follow!()
#==============================================================================#

#Set the 'status' field to 'follow'.
#
    def status_follow!()
        @status = TAC_PLUS_AUTHEN_STATUS_FOLLOW
    end   

#==============================================================================#
# status_getdata?()
#==============================================================================#

#Is the 'status' field set to 'getdata'?
# 
    def status_getdata?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_GETDATA)
        return false
    end   

#==============================================================================#
# status_getdata!()
#==============================================================================#

#Set the 'status' field to 'getdata'.
#
    def status_getdata!()
        @status = TAC_PLUS_AUTHEN_STATUS_GETDATA
    end   

#==============================================================================#
# status_getpass?()
#==============================================================================#

#Is the 'status' field set to 'getpass'?
#
    def status_getpass?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_GETPASS)
        return false
    end   

#==============================================================================#
# status_getpass!()
#==============================================================================#

#Set the 'status' field to 'getpass'.
#
    def status_getpass!()
        @status = TAC_PLUS_AUTHEN_STATUS_GETPASS
    end   

#==============================================================================#
# status_getuser?()
#==============================================================================#

#Is the 'status' field set to 'getuser'?
#
    def status_getuser?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_GETUSER)
        return false
    end   

#==============================================================================#
# status_getuser!()
#==============================================================================#

#Set the 'status' field to 'getuser'.
#
    def status_getuser!()
        @status = TAC_PLUS_AUTHEN_STATUS_GETUSER
    end   

#==============================================================================#
# status_pass?()
#==============================================================================#

#Is the 'status' field set to 'pass'?
#
    def status_pass?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_PASS)
        return false
    end   

#==============================================================================#
# status_pass!()
#==============================================================================#

#Set the 'status' field to 'pass'.
#
    def status_pass!()
        @status = TAC_PLUS_AUTHEN_STATUS_PASS
    end   

#==============================================================================#
# status_restart?()
#==============================================================================#

#Is the 'status' field set to 'restart'?
#
    def status_restart?()
        return true if (@status == TAC_PLUS_AUTHEN_STATUS_RESTART)
        return false
    end   

#==============================================================================#
# status_restart!()
#==============================================================================#

#Set the 'status' field to 'restart'.
#
    def status_restart!()
        @status = TAC_PLUS_AUTHEN_STATUS_RESTART
    end

#==============================================================================#
# xlate_flags()
#==============================================================================#

#Translate 'flags' field into human readable form.
#
    def xlate_flags()
        return("No Echo") if (flag_noecho?)
        return("None")
    end
    
#==============================================================================#
# xlate_status()
#==============================================================================#

#Translate 'status' field into human readable form.
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
        AUTHENTICATION_REPLY_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        AUTHENTICATION_REPLY_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
    def unpack_body(body)
        # fixed fields
        self.status = body.slice!(0)
        self.flags = body.slice!(0)
        self.server_msg_len = body.slice!(0..1)
        self.data_len = body.slice!(0..1)       
       
        # variable-length fields
        self.server_msg = body.slice!(0..(@server_msg_len - 1)) if (@server_msg_len != 0)
        self.data = body.slice!(0..(@data_len - 1)) if (@data_len != 0)
        return(nil)
    end

    
end # class TacacsReply





# A class defining the standard TACACS+ Athentication Continue body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |          user_msg len           |            data len             |
#        +----------------+----------------+----------------+----------------+
#        |     flags      |  user_msg ...
#        +----------------+----------------+----------------+----------------+
#        |    data ...
#        +----------------+
#
# Max size = 131075 bytes
# Min size = 5 bytes
#
class AuthenticationContinue < Authentication #:nodoc: all

# MIXINS
    include TacacsPlus::UserMsg
    include TacacsPlus::Data
    include TacacsPlus::Flags

# CONSTANTS
    
    # flags
    TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01

#==============================================================================#
# flag_abort?()
#==============================================================================#

#Is the 'abort' flag set?
#
    def flag_abort?()
        return(true) if(@flags & TAC_PLUS_CONTINUE_FLAG_ABORT == TAC_PLUS_CONTINUE_FLAG_ABORT)
        return(false)
    end   

#==============================================================================#
# flag_abort!()
#==============================================================================#

#Toggle the 'abort' flag.
#
    def flag_abort!
        if (!flag_abort?)
            @flags = @flags | TAC_PLUS_CONTINUE_FLAG_ABORT
        else
            @flags = @flags & (~TAC_PLUS_CONTINUE_FLAG_ABORT)
        end
        return(nil)
    end

#==============================================================================#
# packed()
#==============================================================================#

#Pack all fields together as a single byte-packed String.
#
    def packed()
        body = TacacsPlus.pack_int_net(@user_msg_len,2) +
               TacacsPlus.pack_int_net(@data_len,2) +
               @flags.chr
               
        body << @user_msg if (@user_msg)
        body << @data if (@data)
        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

#Return a human readable printout of all fields.
#
    def print()
        body = "--- AuthenticationContinue ---\n" +
               "[User Message Length] #{@user_msg_len}\n" +
               "[Data Length] #{@data_len}\n"  +
               "[Flags] #{xlate_flags}" 
               
        body << "\n[User Message] #{@user_msg.gsub(/\n/,"\n" + " " * 15)}"  if (@user_msg)
        body << "\n[Data] #{@data.gsub(/\n/,"\n" + " " * 7)}"  if (@data)
        return(body)
    end    

#==============================================================================#
# reset!()
#==============================================================================#

#Reset all fields to default.
#
    def reset!()
        # fixed-length fields
        @user_msg_len = 0
        @data_len = 0
        @flags = 0
        
        # variable-length fields
        @user_msg = nil
        @data = nil
        return(nil)
    end

#==============================================================================#
# set_len!()
#==============================================================================#

# Set all length fields based on their matching data field.
#
    def set_len!()
        @user_msg_len = @user_msg.length if (@user_msg)
        @data_len = @data.length if (@data) 
        return(nil)
    end

#==============================================================================#
# xlate_flags()
#==============================================================================#

# Translate 'flags' field into human readable form
#
    def xlate_flags()
        return("Abort") if (flag_abort?)
        return("None")
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
        AUTHENTICATION_CONTINUE_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        AUTHENTICATION_CONTINUE_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
    def unpack_body(body)
        # fixed-length fields
        self.user_msg_len = body.slice!(0..1)
        self.data_len = body.slice!(0..1)
        self.flags = body.slice!(0)
        
        # variable-length fields
        @user_msg = body.slice!(0..(@user_msg_len - 1)) if (@user_msg_len != 0)
        @data = body.slice!(0..(@data_len - 1)) if (@data_len != 0)

        return(nil)
    end
    
end # class TacacsContinue

end # module TacacsPlus

__END__

