module TacacsPlus

# A generic class for all TACACS+ Accounting messages.
class Accounting < TacacsBody #:nodoc:

# Is this an Accounting Request message?
    def accounting_request?
        return true if (self.kind_of?(AccountingRequest))
        return false
    end

# Is this an Accounting Reply message?
    def accounting_reply?
        return true if (self.kind_of?(AccountingReply))
        return false
    end
    
end


# A class defining the standard TACACS+ Accounting Request body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |      flags     |  authen_method |    priv_lvl    |  authen_type   |
#        +----------------+----------------+----------------+----------------+
#        | authen_service |    user len    |    port len    |  rem_addr len  |
#        +----------------+----------------+----------------+----------------+
#        |    arg_cnt     |   arg 1 len    |   arg 2 len    |      ...       |
#        +----------------+----------------+----------------+----------------+
#        |   arg N len    |    user ...
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
# Max size = 66310 bytes
# Min size = 9 bytes
#
class AccountingRequest < Accounting #:nodoc: all

# MIXINS
    include TacacsPlus::Flags
    include TacacsPlus::AuthenMethod
    include TacacsPlus::PrivLvl
    include TacacsPlus::AuthenType
    include TacacsPlus::Service
    include TacacsPlus::User
    include TacacsPlus::Port
    include TacacsPlus::RemAddr
    include TacacsPlus::Args

# CONSTANTS
    
    # flags
    TAC_PLUS_ACCT_FLAG_MORE = 0x01 #(deprecated)
    TAC_PLUS_ACCT_FLAG_START = 0x02
    TAC_PLUS_ACCT_FLAG_STOP = 0x04
    TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08

#==============================================================================#
# flag_more?()
#==============================================================================#

#Is the 'more' flag set?
#
    def flag_more?()
        return(true) if(@flags & TAC_PLUS_ACCT_FLAG_MORE == TAC_PLUS_ACCT_FLAG_MORE)
        return(false)
    end   

#==============================================================================#
# flag_more!()
#==============================================================================#

#Toggle the 'more' flag.
#
    def flag_more!
        if (!flag_more?)
            @flags = @flags | TAC_PLUS_ACCT_FLAG_MORE
        else
            @flags = @flags & (~TAC_PLUS_ACCT_FLAG_MORE) 
        end
        return(nil)
    end

#==============================================================================#
# flag_start?()
#==============================================================================#

#Is the 'start' flag set?
#
    def flag_start?()
        return(true) if(@flags & TAC_PLUS_ACCT_FLAG_START == TAC_PLUS_ACCT_FLAG_START)
        return(false)
    end   

#==============================================================================#
# flag_start!()
#==============================================================================#

#Toggle the 'start' flag.
#
    def flag_start!
        if (!flag_start?)
            @flags = @flags | TAC_PLUS_ACCT_FLAG_START
        else
            @flags = @flags & (~TAC_PLUS_ACCT_FLAG_START)
        end
        return(nil)
    end

#==============================================================================#
# flag_stop?()
#==============================================================================#

#Is the 'stop' flag set?
#
    def flag_stop?()
        return(true) if(@flags & TAC_PLUS_ACCT_FLAG_STOP == TAC_PLUS_ACCT_FLAG_STOP)
        return(false)
    end   

#==============================================================================#
# flag_stop!()
#==============================================================================#

#Toggle the 'stop' flag.
#
    def flag_stop!
        if (!flag_stop?)
            @flags = @flags | TAC_PLUS_ACCT_FLAG_STOP
        else
            @flags = @flags & (~TAC_PLUS_ACCT_FLAG_STOP)
        end
        return(nil)
    end

#==============================================================================#
# flag_watchdog?()
#==============================================================================#

#Is the 'watchdog' flag set?
#
    def flag_watchdog?()
        return(true) if(@flags & TAC_PLUS_ACCT_FLAG_WATCHDOG == TAC_PLUS_ACCT_FLAG_WATCHDOG)
        return(false)
    end   

#==============================================================================#
# flag_watchdog!()
#==============================================================================#

#Toggle the 'watchdog' flag.
#
    def flag_watchdog!
        if (!flag_watchdog?)
            @flags = @flags | TAC_PLUS_ACCT_FLAG_WATCHDOG
        else
            @flags = @flags & (~TAC_PLUS_ACCT_FLAG_WATCHDOG)
        end
        return(nil)
    end

#==============================================================================#
# packed()
#==============================================================================#

# Pack all fields together as a single byte-packed String.
#
    def packed()
        body = @flags.chr +
               @authen_method.chr +
               @priv_lvl.chr + 
               @authen_type.chr +
               @service.chr +
               @user_len.chr +
               @port_len.chr +
               @rem_addr_len.chr +
               @arg_cnt.chr
        
        body << @arg_lens.pack('C*') if (@arg_lens.length != 0)
        body << @user if (@user)
        body << @port if (@port)
        body << @rem_addr if (@rem_addr)
        body << @args.join if (@args.length != 0)

        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

# Return a String printout of all fields in YAML format.
#
    def print()
        body = "--- AccountingRequest ---\n" +
               "[Flags] #{xlate_flags}\n" +
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
        @flags = 0
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

#Set all length fields based on their matching data field.
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

#==============================================================================#
# xlate_flags()
#==============================================================================#

#Translate 'flags' field into human readable form.
#
    def xlate_flags()
        flags = []
        flags.push('More') if (flag_more?)
        flags.push('Start') if (flag_start?)
        flags.push('Stop') if (flag_stop?)
        flags.push('Watchdog') if (flag_watchdog?)
        return("#{flags.join(',')}") if (flags.length != 0)
        return("None")
    end


#PRIVATE INSTANCE METHODS
private

#==============================================================================#
# max_size()
#==============================================================================#

# max packet length
    def max_size()
       ACCOUNTING_REQUEST_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet length
    def min_size()
        ACCOUNTING_REQUEST_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
# - Arguments:
#   * String
#
# - Returns:
#   * nil
#
    def unpack_body(body)
        # fixed fields
        self.flags = body.slice!(0)
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
            @arg_lens.each {|x| @args.push( body.slice!( 0..(x - 1) ) )}
        end
   
        return(nil)
    end


end # class AccountingRequest





# A class defining the standard TACACS+ Accounting Reply body.
#
#         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
#        +----------------+----------------+----------------+----------------+
#        |         server_msg len          |            data len             |
#        +----------------+----------------+----------------+----------------+
#        |     status     |         server_msg ...
#        +----------------+----------------+----------------+----------------+
#        |     data ...
#        +----------------+
#
# Max size = 131075 bytes
# Min size = 5 bytes
#
class AccountingReply < Accounting #:nodoc: all

# MIXINS
    include TacacsPlus::ServerMsg
    include TacacsPlus::Data
    include TacacsPlus::Status

# CONSTANTS

    # status
    TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
    TAC_PLUS_ACCT_STATUS_ERROR = 0x02
    TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21
    STATUS_XLATES = {TAC_PLUS_ACCT_STATUS_SUCCESS => "'Success'",
                     TAC_PLUS_ACCT_STATUS_ERROR => "'Error'",
                     TAC_PLUS_ACCT_STATUS_FOLLOW => "'Follow'"}

#==============================================================================#
# packed()
#==============================================================================#

#Pack all fields together as a single byte-packed String.
#
    def packed()
        body = TacacsPlus.pack_int_net(@server_msg_len,2) +
               TacacsPlus.pack_int_net(@data_len,2) + 
               @status.chr
        
        body << @server_msg if (@server_msg)
        body << @data if (@data)

        return(body)
    end

#==============================================================================#
# print()
#==============================================================================#

#Return a String printout of all fields in YAML format.
#
    def print()
        body = "--- AccountingReply ---\n" +
               "[Server Message Length] #{@server_msg_len}\n" +
               "[Data Length] #{@data_len}\n" + 
               "[Status] #{xlate_status}"
        
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
        @server_msg_len = 0
        @data_len = 0
        @status = 0
        
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
        return true if (@status == TAC_PLUS_ACCT_STATUS_ERROR)
        return false
    end   

#==============================================================================#
# status_error!()
#==============================================================================#

#Set the 'status' field to 'error'.
#
    def status_error!()
        @status = TAC_PLUS_ACCT_STATUS_ERROR
    end

#==============================================================================#
# status_follow?()
#==============================================================================#

#Is the 'status' field set to 'follow'?
#
    def status_follow?()
        return true if (@status == TAC_PLUS_ACCT_STATUS_FOLLOW)
        return false
    end   

#==============================================================================#
# status_follow!()
#==============================================================================#

#Set the 'status' field to 'follow'.
#
    def status_follow!()
        @status = TAC_PLUS_ACCT_STATUS_FOLLOW
    end

#==============================================================================#
# status_success?()
#==============================================================================#

#Is the 'status' field set to 'success'?
#
    def status_success?()
        return true if (@status == TAC_PLUS_ACCT_STATUS_SUCCESS)
        return false
    end   

#==============================================================================#
# status_success!()
#==============================================================================#

#Set the 'status' field to 'success'.
#
    def status_success!()
        @status = TAC_PLUS_ACCT_STATUS_SUCCESS
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
        ACCOUNTING_REPLY_MAX_SIZE
    end

#==============================================================================#
# min_size()
#==============================================================================#

# min packet size
    def min_size()
        ACCOUNTING_REPLY_MIN_SIZE
    end

#==============================================================================#
# unpack_body()
#==============================================================================#

# Unpack a byte-packed string into the various fields
#
    def unpack_body(body)
       # fixed-length fields
        self.server_msg_len = body.slice!(0..1)
        self.data_len = body.slice!(0..1)
        self.status = body.slice!(0)
        
        # variable-length fields
        @server_msg = body.slice!(0..(@server_msg_len - 1)) if (@server_msg_len != 0)
        @data = body.slice!(0..(@data_len - 1)) if (@data_len != 0)

        return(nil)
    end


end # class AccountingReply



end # module TacacsPlus

__END__
