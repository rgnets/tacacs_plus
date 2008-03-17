module TacacsPlus

# the 'action' field
module Action #:nodoc: all

#  CONSTANTS
    
    # action
    TAC_PLUS_AUTHEN_LOGIN = 0x01
    TAC_PLUS_AUTHEN_CHPASS = 0x02
    TAC_PLUS_AUTHEN_SENDPASS = 0x03 #(deprecated)
    TAC_PLUS_AUTHEN_SENDAUTH = 0x04
    ACTION_XLATES = {TAC_PLUS_AUTHEN_LOGIN => "Login",
                     TAC_PLUS_AUTHEN_CHPASS => "Change Password",
                     TAC_PLUS_AUTHEN_SENDPASS => "Send Password",
                     TAC_PLUS_AUTHEN_SENDAUTH => "Send Authorization"}

#==============================================================================#
# action=()
#==============================================================================#

#===Synopsis
#Set the 'action' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def action=(val)
        if (val.kind_of?(Integer))
            @action = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @action = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# action_chpass?()
#==============================================================================#

#Is the 'action' field set to 'chpass'?
#
    def action_chpass?()
        return true if (@action == TAC_PLUS_AUTHEN_CHPASS)
        return false
    end   

#==============================================================================#
# action_chpass!()
#==============================================================================#

#Set the 'action' field to 'chpass'.
#
    def action_chpass!()
        @action = TAC_PLUS_AUTHEN_CHPASS
    end   

#==============================================================================#
# action_login?()
#==============================================================================#

#Is the 'action' field set to 'login'?
#
    def action_login?()
        return true if (@action == TAC_PLUS_AUTHEN_LOGIN)
        return false
    end   

#==============================================================================#
# action_login!()
#==============================================================================#

#Set the 'action' field to 'login'.
#
    def action_login!()
        @action = TAC_PLUS_AUTHEN_LOGIN

    end   

#==============================================================================#
# action_sendauth?()
#==============================================================================#

#Is the 'action' field set to 'sendauth'?
#
    def action_sendauth?()
        return true if (@action == TAC_PLUS_AUTHEN_SENDAUTH)
        return false
    end   

#==============================================================================#
# action_sendauth!()
#==============================================================================#

#Set the 'action' field to 'sendauth'.
#
    def action_sendauth!()
        @action = TAC_PLUS_AUTHEN_SENDAUTH
    end   

#==============================================================================#
# action_sendpass?()
#==============================================================================#

#Is the 'action' field set to 'sendpass'?
#
    def action_sendpass?()
        return true if (@action == TAC_PLUS_AUTHEN_SENDPASS)
        return false
    end   

#==============================================================================#
# action_sendpass!()
#==============================================================================#

#Set the 'action' field to 'sendpass'.
#
    def action_sendpass!()
        @action = TAC_PLUS_AUTHEN_SENDPASS
    end    

#==============================================================================#
# xlate_action()
#==============================================================================#

# Translate 'action' field into human readable form.
#
    def xlate_action()
        return ACTION_XLATES[@action] if (ACTION_XLATES.has_key?(@action))
        return(@action.to_s)     
    end

attr_reader :action
end # end module Action



# the 'args' field
module Args #:nodoc: all

#==============================================================================#
# args=()
#==============================================================================#

#===Synopsis
#Replace all 'arg' fields. Up to 255 elements of 0-255 bytes each.
#
#===Arguments
#* Array of Strings
#
#===Returns
#* nil
#
    def args=(val)
        if (val.kind_of?(Array))
            raise ArgumentError, "Provided Array exceeds limit of 255 elements." if (val.length > 255)
            @args.clear
            val.each do |x|
                raise ArgumentError, "Element of provided Array was not a String, but a #{x.class}." if (!x.kind_of?(String))
                raise ArgumentError, "#{x} exceeds limit of 255 bytes." if (x.length > 255)
                @args.push(x)
            end
        else
            raise ArgumentError, "Expected Array, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# arg_cnt=()
#==============================================================================#

#===Synopsis
#Set the 'arg_cnt' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def arg_cnt=(val)     
        if (val.kind_of?(Integer))
            @arg_cnt = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)
            @arg_cnt = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# arg_lens=()
#==============================================================================#

#===Synopsis
#Replace all 'arg_len' fields. Up to 255 elements of 1-byte each.
#
#===Arguments
#* Array of byte-packed Strings or Integers
#
#===Returns
#* nil
#
   def arg_lens=(val)
        if (val.kind_of?(Array))
            raise ArgumentError, "Provided Array exceeds limit of 255 elements." if (val.length > 255)
            @arg_lens.clear
            val.each do |x|
                if (x.kind_of?(Integer))
                    @arg_lens.push(x & 0xff)
                elsif (x.kind_of?(String))
                    raise ArgumentError, "Array element #{x} exceeds size limit of 1 byte." if (x.length != 1)
                    @arg_lens.push(x.unpack('C')[0])
                else
                    raise ArgumentError, "Element of provided Array was not a String or Integer, but a #{x.class}."
                end
            end
        else
            raise ArgumentError, "Expected Array but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :args
attr_reader :arg_cnt
attr_reader :arg_lens

end # end module Args



# the 'authen_method' field
module AuthenMethod #:nodoc: all

# CONSTANTS

    TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00
    TAC_PLUS_AUTHEN_METH_NONE = 0x01
    TAC_PLUS_AUTHEN_METH_KRB5 = 0x02
    TAC_PLUS_AUTHEN_METH_LINE = 0x03
    TAC_PLUS_AUTHEN_METH_ENABLE = 0x04
    TAC_PLUS_AUTHEN_METH_LOCAL = 0x05
    TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06
    TAC_PLUS_AUTHEN_METH_GUEST = 0x08
    TAC_PLUS_AUTHEN_METH_RADIUS = 0x10
    TAC_PLUS_AUTHEN_METH_KRB4 = 0x11
    TAC_PLUS_AUTHEN_METH_RCMD = 0x20
    AUTHEN_METHOD_XLATES = {TAC_PLUS_AUTHEN_METH_NOT_SET => "Not Set",
                            TAC_PLUS_AUTHEN_METH_NONE => "None",
                            TAC_PLUS_AUTHEN_METH_KRB5 => "KRB5",
                            TAC_PLUS_AUTHEN_METH_LINE => "Line",
                            TAC_PLUS_AUTHEN_METH_ENABLE => "Enable",
                            TAC_PLUS_AUTHEN_METH_LOCAL => "Local",
                            TAC_PLUS_AUTHEN_METH_TACACSPLUS => "TACACS Plus",
                            TAC_PLUS_AUTHEN_METH_GUEST => "Guest",
                            TAC_PLUS_AUTHEN_METH_RADIUS => "Radius",
                            TAC_PLUS_AUTHEN_METH_KRB4 => "KRB4",
                            TAC_PLUS_AUTHEN_METH_RCMD => "RCMD"}

#==============================================================================#
# authen_method=()
#==============================================================================#

#===Synopsis
#Set the 'authen_method' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def authen_method=(val)
        if (val.kind_of?(Integer))
            @authen_method = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @authen_method = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end
    
#==============================================================================#
# authen_method_notset?()
#==============================================================================#

#Is the 'authen_method' field set to 'notset'?
#
    def authen_method_notset?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_NOT_SET)
        return false
    end   

#==============================================================================#
# authen_method_notset!()
#==============================================================================#

#Set the 'authen_method' field to 'notset'.
#
    def authen_method_notset!()
        @authen_method = TAC_PLUS_AUTHEN_METH_NOT_SET
    end

#==============================================================================#
# authen_method_none?()
#==============================================================================#

#Is the 'authen_method' field set to 'none'?
#
    def authen_method_none?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_NONE)
        return false
    end   

#==============================================================================#
# authen_method_none!()
#==============================================================================#

#Set the 'authen_method' field to 'none'.
#
    def authen_method_none!()
        @authen_method = TAC_PLUS_AUTHEN_METH_NONE
    end

#==============================================================================#
# authen_method_krb5?()
#==============================================================================#

#Is the 'authen_method' field set to 'krb5'?
#
    def authen_method_krb5?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_KRB5)
        return false
    end   

#==============================================================================#
# authen_method_krb5!()
#==============================================================================#

#Set the 'authen_method' field to 'krb5'.
#
    def authen_method_krb5!()
        @authen_method = TAC_PLUS_AUTHEN_METH_KRB5
    end

#==============================================================================#
# authen_method_line?()
#==============================================================================#

#Is the 'authen_method' field set to 'line'?
#
    def authen_method_line?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_LINE)
        return false
    end   

#==============================================================================#
# authen_method_line!()
#==============================================================================#

#Set the 'authen_method' field to 'line'.
#
    def authen_method_line!()
        @authen_method = TAC_PLUS_AUTHEN_METH_LINE
    end
    
#==============================================================================#
# authen_method_enable?()
#==============================================================================#

#Is the 'authen_method' field set to 'enable'?
#
    def authen_method_enable?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_ENABLE)
        return false
    end   

#==============================================================================#
# authen_method_enable!()
#==============================================================================#

#Set the 'authen_method' field to 'enable'.
#
    def authen_method_enable!()
        @authen_method = TAC_PLUS_AUTHEN_METH_ENABLE
    end

#==============================================================================#
# authen_method_local?()
#==============================================================================#

#Is the 'authen_method' field set to 'local'?
#
    def authen_method_local?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_LOCAL)
        return false
    end   

#==============================================================================#
# authen_method_local!()
#==============================================================================#

#Set the 'authen_method' field to 'local'.
#
    def authen_method_local!()
        @authen_method = TAC_PLUS_AUTHEN_METH_LOCAL
    end

#==============================================================================#
# authen_method_tacacsplus?()
#==============================================================================#

#Is the 'authen_method' field set to 'tacacsplus'?
#
    def authen_method_tacacsplus?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_TACACSPLUS)
        return false
    end   

#==============================================================================#
# authen_method_tacacsplus!()
#==============================================================================#

#Set the 'authen_method' field to 'tacacsplus'.
#
    def authen_method_tacacsplus!()
        @authen_method = TAC_PLUS_AUTHEN_METH_TACACSPLUS
    end

#==============================================================================#
# authen_method_guest?()
#==============================================================================#

#Is the 'authen_method' field set to 'guest'?
#
    def authen_method_guest?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_GUEST)
        return false
    end   

#==============================================================================#
# authen_method_guest!()
#==============================================================================#

#Set the 'authen_method' field to 'guest'.
#
    def authen_method_guest!()
        @authen_method = TAC_PLUS_AUTHEN_METH_GUEST
    end

#==============================================================================#
# authen_method_radius?()
#==============================================================================#

#Is the 'authen_method' field set to 'radius'?
#
    def authen_method_radius?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_RADIUS)
        return false
    end   

#==============================================================================#
# authen_method_radius!()
#==============================================================================#

#Set the 'authen_method' field to 'radius'.
#
    def authen_method_radius!()
        @authen_method = TAC_PLUS_AUTHEN_METH_RADIUS
    end

#==============================================================================#
# authen_method_krb4?()
#==============================================================================#

#Is the 'authen_method' field set to 'krb4'?
#
    def authen_method_krb4?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_KRB4)
        return false
    end   

#==============================================================================#
# authen_method_krb4!()
#==============================================================================#

#Set the 'authen_method' field to 'krb4'.
#
    def authen_method_krb4!()
        @authen_method = TAC_PLUS_AUTHEN_METH_KRB4
    end

#==============================================================================#
# authen_method_rcmd?()
#==============================================================================#

#Is the 'authen_method' field set to 'rcmd'?
#
    def authen_method_rcmd?()
        return true if (@authen_method == TAC_PLUS_AUTHEN_METH_RCMD)
        return false
    end   

#==============================================================================#
# authen_method_rcmd!()
#==============================================================================#

#Set the 'authen_method' field to 'rcmd'.
#
    def authen_method_rcmd!()
        @authen_method = TAC_PLUS_AUTHEN_METH_RCMD
    end

#==============================================================================#
# xlate_authen_method()
#==============================================================================#

# Translate 'authen_method' field into human readable form.
#
    def xlate_authen_method()
        return AUTHEN_METHOD_XLATES[@authen_method] if (AUTHEN_METHOD_XLATES.has_key?(@authen_method))
        return(@authen_method.to_s)     
    end
    
attr_reader :authen_method
end # end module AuthenMethod


# the 'authen_type' field
module AuthenType #:nodoc: all

# CONSTANTS

    TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
    TAC_PLUS_AUTHEN_TYPE_PAP = 0x02
    TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03
    TAC_PLUS_AUTHEN_TYPE_ARAP = 0x04
    TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05
    AUTHEN_TYPE_XLATES = {TAC_PLUS_AUTHEN_TYPE_ASCII => "ASCII",
                          TAC_PLUS_AUTHEN_TYPE_PAP => "PAP",
                          TAC_PLUS_AUTHEN_TYPE_CHAP => "CHAP",
                          TAC_PLUS_AUTHEN_TYPE_ARAP => "ARAP",
                          TAC_PLUS_AUTHEN_TYPE_MSCHAP => "MSCHAP"}

#==============================================================================#
# authen_type=()
#==============================================================================#

#===Synopsis
#Set the 'authen_type' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def authen_type=(val)
        if (val.kind_of?(Integer))
            @authen_type = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @authen_type = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# authen_type_arap?()
#==============================================================================#

#Is the 'authen_type' field set to 'arap'?
#
    def authen_type_arap?()
        return true if (@authen_type == TAC_PLUS_AUTHEN_TYPE_ARAP)
        return false
    end 
 
#==============================================================================#
# authen_type_arap!()
#==============================================================================#

#Set the 'authen_type' field to 'arap'.
#
    def authen_type_arap!()
        @authen_type = TAC_PLUS_AUTHEN_TYPE_ARAP
    end   
   
#==============================================================================#
# authen_type_ascii?()
#==============================================================================#

#Is the 'authen_type' field set to 'ascii'?
#
    def authen_type_ascii?()
        return true if (@authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII)
        return false
    end   

#==============================================================================#
# authen_type_ascii!()
#==============================================================================#

#Set the 'authen_type' field to 'ascii'.
#
    def authen_type_ascii!()
        @authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII
    end   

#==============================================================================#
# authen_type_chap?()
#==============================================================================#

#Is the 'authen_type' field set to 'chap'?
#
    def authen_type_chap?()
        return true if (@authen_type == TAC_PLUS_AUTHEN_TYPE_CHAP)
        return false
    end   

#==============================================================================#
# authen_type_chap!()
#==============================================================================#

#Set the 'authen_type' field to 'chap'.
#
    def authen_type_chap!()
        @authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP
    end   

#==============================================================================#
# authen_type_mschap?()
#==============================================================================#

#Is the 'authen_type' field set to 'mschap'?
#
    def authen_type_mschap?()
        return true if (@authen_type == TAC_PLUS_AUTHEN_TYPE_MSCHAP)
        return false
    end   

#==============================================================================#
# authen_type_mschap!()
#==============================================================================#

#Set the 'authen_type' field to 'mschap'.
# 
    def authen_type_mschap!()
        @authen_type = TAC_PLUS_AUTHEN_TYPE_MSCHAP
    end   

#==============================================================================#
# authen_type_pap?()
#==============================================================================#

#Is the 'authen_type' field set to 'pap'?
#
    def authen_type_pap?()
        return true if (@authen_type == TAC_PLUS_AUTHEN_TYPE_PAP)
        return false
    end   

#==============================================================================#
# authen_type_pap!()
#==============================================================================#

#Set the 'authen_type' field to 'pap'.
#
    def authen_type_pap!()
        @authen_type = TAC_PLUS_AUTHEN_TYPE_PAP
    end

#==============================================================================#
# xlate_authen_type()
#==============================================================================#

# Translate 'authen_type' field into human readable form.
#
    def xlate_authen_type()
        return AUTHEN_TYPE_XLATES[@authen_type] if (AUTHEN_TYPE_XLATES.has_key?(@authen_type))
        return(@authen_type.to_s)     
    end

attr_reader :authen_type
end # end module AuthenType



# the 'data' field
module Data #:nodoc: all

attr_reader :data

#==============================================================================#
# data=()
#==============================================================================#

#===Synopsis
#Set the 'data' field. 0 - 65535 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def data=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**(8*data_len_bytes)-1} byes." if (val.length > 2**(8*data_len_bytes)-1)
            @data = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end


#==============================================================================#
# data_len=()
#==============================================================================#

#===Synopsis
#Set the 'data_len' field. 1 or 2 bytes.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def data_len=(val)
        if (val.kind_of?(Integer))
            @data_len = val & (2**(8*data_len_bytes)-1)           
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be #{data_len_bytes}-byte, " +
                                 "but was #{val.length}." if (val.length != data_len_bytes)

            if (data_len_bytes == 2)
                @data_len = val.unpack('n')[0]
            elsif (data_len_bytes == 1)
                @data_len = val.unpack('C')[0]        
            else
                raise "Unsupported data_len field size #{data_len_bytes}"
            end
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :data
attr_reader :data_len
end # end module Data



# the 'flags' field
module Flags #:nodoc: all
#==============================================================================#
# flags=()
#==============================================================================#

#===Synopsis
#Set the 'flags' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def flags=(val)
        if (val.kind_of?(Integer))
            @flags = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @flags = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# flags_clear!()
#==============================================================================#

#Clear all flags.
#
    def flags_clear!()
        @flags = 0
    end

attr_reader :flags
end # end module Flags



# the 'Length' field
module Length #:nodoc: all

#==============================================================================#
# length=()
#==============================================================================#

#===Synopsis
#Set the 'length' field. 4-bytes.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def length=(val)
        if (val.kind_of?(Integer))
            @length = val & 0xffffffff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 4-bytes, but was #{val.length}." if (val.length != 4)                
            @length = val.unpack('N')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
    end

attr_reader :length
end # end module Length



# the 'port' field
module Port #:nodoc: all

attr_reader :port

#==============================================================================#
# port=()
#==============================================================================#

#===Synopsis
#Set the 'port' field. 0 - 255 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def port=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**8-1} byes." if (val.length > 2**8-1)
            @port = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end


#==============================================================================#
# port_len=()
#==============================================================================#

#===Synopsis
#Set the 'port_len' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def port_len=(val)
        if (val.kind_of?(Integer))
            @port_len = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @port_len = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :port
attr_reader :port_len
end # end module Port



# the 'priv_lvl' field
module PrivLvl #:nodoc: all

#==============================================================================#
# priv_lvl=()
#==============================================================================#

#===Synopsis
#Set the 'priv_lvl' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def priv_lvl=(val)
        if (val.kind_of?(Integer))
            @priv_lvl = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @priv_lvl = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :priv_lvl
end # end module PrivLvl



# the 'rem_addr' field
module RemAddr #:nodoc: all

attr_reader :rem_addr

#==============================================================================#
# rem_addr=()
#==============================================================================#

#===Synopsis
#Set the 'rem_addr' field. 0 - 255 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def rem_addr=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**8-1} byes." if (val.length > 2**8-1)
            @rem_addr = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# rem_addr_len=()
#==============================================================================#

#===Synopsis
#Set the 'rem_addr_len' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def rem_addr_len=(val)
        if (val.kind_of?(Integer))
            @rem_addr_len = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @rem_addr_len = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :rem_addr
attr_reader :rem_addr_len
end # end module RemAddr


# the 'seq_no' field
module SeqNo #:nodoc: all

#==============================================================================#
# dec_seq_no!()
#==============================================================================#

# Decrement the sequence number field by 1.
#
    def dec_seq_no!()
        @seq_no -= 1 if (@seq_no > 0)        
        return(nil)
    end

#==============================================================================#
# inc_seq_no!()
#==============================================================================#

# Increment the sequence number field by 1.
#
    def inc_seq_no!()
        @seq_no += 1
        return(nil)
    end

#==============================================================================#
# seq_no=()
#==============================================================================#

#===Synopsis
#Set the 'seq_no' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def seq_no=(val)
        if (val.kind_of?(Integer))
            @seq_no = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value should be 1-byte, but was #{val.length}." if (val.length != 1)                
            @seq_no = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
    end

attr_reader :seq_no
end # end module SeqNo


# the 'server_msg' field
module ServerMsg #:nodoc: all

attr_reader :server_msg

#==============================================================================#
# server_msg=()
#==============================================================================#

#===Synopsis
#Set the 'server_msg' field. 0 - 255 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def server_msg=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**16-1} byes." if (val.length > 2**16-1)
            @server_msg = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# server_msg_len=()
#==============================================================================#

#===Synopsis
#Set the 'server_msg_len' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def server_msg_len=(val)
        if (val.kind_of?(Integer))
            @server_msg_len = val & 0xffff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 2-bytes, but was #{val.length}." if (val.length != 2)                
            @server_msg_len = val.unpack('n')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :server_msg
attr_reader :server_msg_len
end # end module ServerMsg


# the 'service' field
module Service #:nodoc: all

#  CONSTANTS

    # service
    TAC_PLUS_AUTHEN_SVC_NONE = 0x00
    TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01
    TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02
    TAC_PLUS_AUTHEN_SVC_PPP = 0x03
    TAC_PLUS_AUTHEN_SVC_ARAP = 0x04
    TAC_PLUS_AUTHEN_SVC_PT = 0x05
    TAC_PLUS_AUTHEN_SVC_RCMD = 0x06
    TAC_PLUS_AUTHEN_SVC_X25 = 0x07
    TAC_PLUS_AUTHEN_SVC_NASI = 0x08
    TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09
    SERVICE_XLATES = {TAC_PLUS_AUTHEN_SVC_NONE => "None",
                      TAC_PLUS_AUTHEN_SVC_LOGIN => "Login",
                      TAC_PLUS_AUTHEN_SVC_ENABLE => "Enable",
                      TAC_PLUS_AUTHEN_SVC_PPP => "PPP",
                      TAC_PLUS_AUTHEN_SVC_ARAP => "ARAP",
                      TAC_PLUS_AUTHEN_SVC_PT => "PT",
                      TAC_PLUS_AUTHEN_SVC_RCMD => "RCMD",
                      TAC_PLUS_AUTHEN_SVC_X25 => "X25",
                      TAC_PLUS_AUTHEN_SVC_NASI => "NASI",
                      TAC_PLUS_AUTHEN_SVC_FWPROXY => "FWPROXY"}

#==============================================================================#
# service=()
#==============================================================================#

#===Synopsis
#Set the 'authen_service' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def service=(val)
        if (val.kind_of?(Integer))
            @service = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @service = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# service_arap?()
#==============================================================================#

#Is the 'service' field set to 'arap'?
#
    def service_arap?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_ARAP)
        return false
    end   

#==============================================================================#
# service_arap!()
#==============================================================================#

#Set the 'service' field to 'arap'.
#
    def service_arap!()
        @service = TAC_PLUS_AUTHEN_SVC_ARAP
    end  

#==============================================================================#
# service_enable?()
#==============================================================================#

#Is the 'service' field set to 'enable'?
#
    def service_enable?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_ENABLE)
        return false
    end   

#==============================================================================#
# service_enable!()
#==============================================================================#

#Set the 'service' field to 'enable'.
#
    def service_enable!()
        @service = TAC_PLUS_AUTHEN_SVC_ENABLE
    end   

#==============================================================================#
# service_fwproxy?()
#==============================================================================#

#Is the 'service' field set to 'fwproxy'?
#
    def service_fwproxy?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_FWPROXY)
        return false
    end   

#==============================================================================#
# service_fwproxy!()
#==============================================================================#

#Set the 'service' field to 'fwproxy'.
#
    def service_fwproxy!()
        @service = TAC_PLUS_AUTHEN_SVC_FWPROXY
    end   

#==============================================================================#
# service_login?()
#==============================================================================#

#Is the 'service' field set to 'login'?
#
    def service_login?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_LOGIN)
        return false
    end   

#==============================================================================#
# service_login!()
#==============================================================================#

#Set the 'service' field to 'login'.
#
    def service_login!()
        @service = TAC_PLUS_AUTHEN_SVC_LOGIN
    end   

#==============================================================================#
# service_nasi?()
#==============================================================================#

#Is the 'service' field set to 'nasi'?
#
    def service_nasi?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_NASI)
        return false
    end   

#==============================================================================#
# service_nasi!()
#==============================================================================#

#Set the 'service' field to 'nasi'.
#
    def service_nasi!()
        @service = TAC_PLUS_AUTHEN_SVC_NASI
    end   

#==============================================================================#
# service_none?()
#==============================================================================#

#Is the 'service' field set to 'none'?
#
    def service_none?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_NONE)
        return false
    end   

#==============================================================================#
# service_none!()
#==============================================================================#

#Set the 'service' field to 'none'.
#
    def service_none!()
        @service = TAC_PLUS_AUTHEN_SVC_NONE
    end   

#==============================================================================#
# service_ppp?()
#==============================================================================#

#Is the 'service' field set to 'ppp'?
#
    def service_ppp?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_PPP)
        return false
    end   

#==============================================================================#
# service_ppp!()
#==============================================================================#

#Set the 'service' field to 'ppp'.
#
    def service_ppp!()
        @service = TAC_PLUS_AUTHEN_SVC_PPP
    end   

#==============================================================================#
# service_pt?()
#==============================================================================#

#Is the 'service' field set to 'pt'?
#
    def service_pt?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_PT)
        return false
    end   

#==============================================================================#
# service_pt!()
#==============================================================================#

#Set the 'service' field to 'pt'.
#
    def service_pt!()
        @service = TAC_PLUS_AUTHEN_SVC_PT
    end   

#==============================================================================#
# service_rcmd?()
#==============================================================================#

#Is the 'service' field set to 'rcmd'?
#
    def service_rcmd?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_RCMD)
        return false
    end   

#==============================================================================#
# service_rcmd!()
#==============================================================================#

#Set the 'service' field to 'rcmd'.
#
    def service_rcmd!()
        @service = TAC_PLUS_AUTHEN_SVC_RCMD
    end   

#==============================================================================#
# service_x25?()
#==============================================================================#

#Is the 'service' field set to 'x25'?
#
    def service_x25?()
        return true if (@service == TAC_PLUS_AUTHEN_SVC_X25)
        return false
    end   

#==============================================================================#
# service_x25!()
#==============================================================================#

#Set the 'service' field to 'x25'.
#
    def service_x25!()
        @service = TAC_PLUS_AUTHEN_SVC_X25
    end

#==============================================================================#
# xlate_service()
#==============================================================================#

# Translate 'service' field into human readable form.
#
    def xlate_service()
        return SERVICE_XLATES[@service] if (SERVICE_XLATES.has_key?(@service))
        return(@service.to_s)     
    end

attr_reader :service
alias :authen_service :service
alias :authen_service= :service=
end # end module Service


# the 'session_id' field
module SessionId #:nodoc: all

#==============================================================================#
# randomize_session_id!()
#==============================================================================#

# Set the 'session_id' field to a random value.
#
    def randomize_session_id!()
        @session_id = rand(2**32-1)
        return(nil)
    end

#==============================================================================#
# session_id=()
#==============================================================================#

#===Synopsis
#Set the 'session_id' field. 4-bytes.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def session_id=(val)
        if (val.kind_of?(Integer))
            @session_id = val & 0xffffffff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 4-bytes, but was #{val.length}." if (val.length != 4)                
            @session_id = val.unpack('N')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
    end

attr_reader :session_id
end # end module SessionId


# the 'status' field
module Status #:nodoc: all

#==============================================================================#
# status=()
#==============================================================================#

#===Synopsis
#Set the 'status' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def status=(val)
        if (val.kind_of?(Integer))
            @status = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)
            @status = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :status
end #end module Status


# the 'type' field
module Type #:nodoc: all

#  CONSTANTS  
    
    # type
    TAC_PLUS_AUTHEN = 0x01 # Authentication
    TAC_PLUS_AUTHOR = 0x02 # Authorization
    TAC_PLUS_ACCT = 0x03 #Accounting
    TYPE_XLATES = {TAC_PLUS_AUTHEN => "Authentication",
                   TAC_PLUS_AUTHOR => "Authorization",
                   TAC_PLUS_ACCT => "Accounting"}

#==============================================================================#
# type=()
#==============================================================================#

#===Synopsis
#Set the 'type' field.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def type=(val)
        if (val.kind_of?(Integer))
            @type = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value should be 1-byte, but was #{val.length}." if (val.length != 1)                
            @type = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
    end
    

#==============================================================================#
# type_accounting?()
#==============================================================================#

#Is the 'type' field set to 'accounting'?
#
    def type_accounting?()
        return(true) if(@type == TAC_PLUS_ACCT)
        return(false)
    end

#==============================================================================#
# type_accounting!()
#==============================================================================#

#Set the 'type' field to 'accounting'.
#
    def type_accounting!()
        @type = TAC_PLUS_ACCT
    end

#==============================================================================#
# type_authentication?()
#==============================================================================#

#Is the 'type' field set to 'authentication'?
#
    def type_authentication?()
        return(true) if(@type == TAC_PLUS_AUTHEN)
        return(false)
    end

#==============================================================================#
# type_authentication!()
#==============================================================================#

#Set the 'type' field to 'authentication'.
#
    def type_authentication!()
        @type = TAC_PLUS_AUTHEN
    end

#==============================================================================#
# type_authorization?()
#==============================================================================#

#Is the 'type' field set to 'authorization'?
#
    def type_authorization?()
        return(true) if(@type == TAC_PLUS_AUTHOR)
        return(false)
    end

#==============================================================================#
# type_authorization!()
#==============================================================================#

#Set the 'type' field to 'authorization'.
#
    def type_authorization!()
        @type = TAC_PLUS_AUTHOR
    end

#==============================================================================#
# xlate_type()
#==============================================================================#

# Translate 'type' field into human readable form.
#
    def xlate_type()
        return TYPE_XLATES[@type] if (TYPE_XLATES.has_key?(@type))
        return(@type.to_s)     
    end

attr_reader :type
end # end module Type


# the 'user' field
module User #:nodoc: all

attr_reader :user

#==============================================================================#
# user=()
#==============================================================================#

#===Synopsis
#Set the 'user' field. 0 - 255 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def user=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**8-1} byes." if (val.length > 2**8-1)
            @user = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# user_len=()
#==============================================================================#

#===Synopsis
#Set the 'user_len' field. 1-byte.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
# - Notes:
#   
#
    def user_len=(val)
        if (val.kind_of?(Integer))
            @user_len = val & 0xff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 1-byte, but was #{val.length}." if (val.length != 1)                
            @user_len = val.unpack('C')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :user
attr_reader :user_len
end # module User



# the 'user_msg' field
module UserMsg #:nodoc: all

    attr_reader :user_msg

#==============================================================================#
# user_msg=()
#==============================================================================#

#===Synopsis
#Set the 'user_msg' field. 0 - 65535 bytes
#
#===Arguments
#* byte-packed String
#
#===Returns
#* nil
#
    def user_msg=(val)
        if(val.kind_of?(String))                
            raise ArgumentError, "#{val.length}-byte value exceeds limit of #{2**16-1} byes." if (val.length > 2**16-1)
            @user_msg = val
        else
            raise ArgumentError, "Expected String, but #{val.class} provided." 
        end
        return(nil)
    end

#==============================================================================#
# user_msg_len=()
#==============================================================================#

#===Synopsis
#Set the 'user_msg_len' field. 2-bytes.
#
#===Arguments
#* byte-packed String, or an Integer
#
#===Returns
#* nil
#
    def user_msg_len=(val)
        if (val.kind_of?(Integer))
            @user_msg_len = val & 0xffff
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value must be 2-bytes, but was #{val.length}." if (val.length != 2)                
            @user_msg_len = val.unpack('n')[0]
        else
            raise ArgumentError, "Expected String or Integer, but #{val.class} provided." 
        end
        return(nil)
    end

attr_reader :user_msg
attr_reader :user_msg_len
end # end module UserMsg


# The 'major_version' and 'minor_version' fields
module Version #:nodoc: all

#  CONSTANTS

    # major ver
    TAC_PLUS_MAJOR_VER = 0xc
    
    # minor ver
    TAC_PLUS_MINOR_VER_DEFAULT = 0x0
    TAC_PLUS_MINOR_VER_ONE = 0x1
    MAJ_VERSION_XLATES = {TAC_PLUS_MAJOR_VER => "Default"}
    MIN_VERSION_XLATES = {TAC_PLUS_MINOR_VER_DEFAULT => "Default",
                          TAC_PLUS_MINOR_VER_ONE => "One"}

#==============================================================================#
# major_version=()
#==============================================================================#

#===Synopsis
#Set the 'major version' field. 4-bits.
#
#===Arguments
#* Integer
#
#===Returns
#* nil 
#
    def major_version=(val)
        if (val.kind_of?(Integer))
            @major_version = val & 0xf
        else
            raise ArgumentError, "Expected Integer, but #{val.class} provided." 
        end        
    end

#==============================================================================#
# minor_version=()
#==============================================================================#

#===Synopsis
#Set the 'minor version' field. 4-bits.
#
#===Arguments
#* Integer
#
#===Returns
#* nil 
#    
    def minor_version=(val)
        if (val.kind_of?(Integer))
            @minor_version = val & 0xf
        else
            raise ArgumentError, "Expected Integer, but #{val.class} provided." 
        end        
    end

#==============================================================================#
# minor_version_default?()
#==============================================================================#

#Is the 'minor version' field set to 0?
    def minor_version_default?
        return true if (@minor_version == 0)
        return false
    end

#==============================================================================#
# minor_version_default!()
#==============================================================================#

#Set the 'minor version' field to 0?
    def minor_version_default!
        self.minor_version = 0
    end

#==============================================================================#
# minor_version_one?()
#==============================================================================#

#Is the 'minor version' field set to 1?
    def minor_version_one?
        return true if (@minor_version == 1)
        return false
    end

#==============================================================================#
# minor_version_one!()
#==============================================================================#

#Set the 'minor version' field to 1?
    def minor_version_one!
        self.minor_version = 1
    end

#==============================================================================#
# version()
#==============================================================================#

    def version()
        version = (@major_version << 4) | @minor_version
    end

#==============================================================================#
# version=()
#==============================================================================#

#===Synopsis
#Set both the 'major version' and 'minor version' fields. 1-byte.
#
#===Arguments
#* Integer
#
#===Returns
#* nil 
#
    def version=(val)
        if (val.kind_of?(Integer))            
            make_major_minor_version(val & 0xff)
        elsif(val.kind_of?(String))
            raise ArgumentError, "Value should be 1-byte, but was #{val.length}." if (val.length != 1)                
            make_major_minor_version(val.unpack('C')[0])
        else
            raise ArgumentError, "Expected Integer, but #{val.class} provided." 
        end
    end

#==============================================================================#
# xlate_major_version()
#==============================================================================#

# Translate 'major version' field into human readable form.
#
    def xlate_major_version()
        return MAJ_VERSION_XLATES[@major_version] if (MAJ_VERSION_XLATES.has_key?(@major_version))
        return(@major_version.to_s)     
    end

#==============================================================================#
# xlate_minor_version()
#==============================================================================#

# Translate 'minor version' field into human readable form.
#
    def xlate_minor_version()
        return MIN_VERSION_XLATES[@minor_version] if (MIN_VERSION_XLATES.has_key?(@minor_version))
        return(@minor_version.to_s)     
    end

attr_reader :major_version
attr_reader :minor_version

# PRIVATE INSTANT METHODS
private


#==============================================================================#
# make_major_minor_version()
#==============================================================================#

# make @major_version and @minor_version from @version_str
#
    def make_major_minor_version(version)
        @major_version = version >> 4
        @minor_version = version & 0xf
    end

end # module Version

end # module TacacsPlus

__END__
