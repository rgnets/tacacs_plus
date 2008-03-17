#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestAuthentication < Test::Unit::TestCase
    
    def test_start_new
        body = TacacsPlus::AuthenticationStart.new
        body.action = 1
        body.priv_lvl = 1
        body.authen_type = 1
        body.service = 1
        body.user_len = 4
        body.port_len = 4
        body.rem_addr_len = 4
        body.data_len = 4
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.data = 'test'        
        
        body2 = TacacsPlus::AuthenticationStart.new(body.packed)
        
        assert_not_nil(body2)
        assert_equal(body2.action,body.action)
        assert_equal(body2.priv_lvl,body.priv_lvl)
        assert_equal(body2.authen_type,body.authen_type)
        assert_equal(body2.service,body.service)
        assert_equal(body2.user_len,body.user_len)
        assert_equal(body2.port_len,body.port_len)
        assert_equal(body2.rem_addr_len,body.rem_addr_len)
        assert_equal(body2.data_len,body.data_len)
        assert_equal(body2.user,body.user)
        assert_equal(body2.port,body.port)
        assert_equal(body2.rem_addr,body.rem_addr)
        assert_equal(body2.data,body.data)
        
        assert_raise(ArgumentError){TacacsPlus::AuthenticationStart.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AuthenticationStart.new('A' * 1029)}
    end
    
    def test_start_packed
        body = TacacsPlus::AuthenticationStart.new
        assert_kind_of(String,body.packed)
        
        assert_equal(8,body.packed.length)
        
        body.user = 'A' * 255
        body.port = 'A' * 255
        body.rem_addr = 'A' * 255
        body.data = 'A' * 255
        
        assert_equal(1028,body.packed.length)        
    end
    
    def test_start_print
        body = TacacsPlus::AuthenticationStart.new
        assert_kind_of(String,body.print)
    end
    
    def test_start_set_len
        body = TacacsPlus::AuthenticationStart.new
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.data = 'test'
        body.set_len!
        assert_equal(4,body.user_len)
        assert_equal(4,body.port_len)
        assert_equal(4,body.rem_addr_len)
        assert_equal(4,body.data_len)
    end
    
    
    
    
    # reply
    def test_reply_new
        body = TacacsPlus::AuthenticationReply.new        
        body.status = 1
        body.flags = 1
        body.server_msg_len = 4
        body.data_len = 4
        body.server_msg = 'test'
        body.data = 'test'
        
        body2 = TacacsPlus::AuthenticationReply.new(body.packed)
        assert_not_nil(body2)
        
        assert_equal(body2.status,body.status)
        assert_equal(body2.flags,body.flags)
        assert_equal(body2.server_msg_len,body.server_msg_len)
        assert_equal(body2.data_len,body.data_len)
        assert_equal(body2.server_msg,body.server_msg)
        assert_equal(body2.data,body.data)        
        
        assert_raise(ArgumentError){TacacsPlus::AuthenticationReply.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AuthenticationReply.new('A' * 131077)}
    end
    
    def test_reply_status
        body = TacacsPlus::AuthenticationReply.new
        
        body.status_pass!
        assert_equal(true,body.status_pass?)
        assert_equal(1,body.status)
        
        body.status_fail!
        assert_equal(true,body.status_fail?)
        assert_equal(2,body.status)
        
        body.status_getdata!
        assert_equal(true,body.status_getdata?)
        assert_equal(3,body.status)
        
        body.status_getuser!
        assert_equal(true,body.status_getuser?)
        assert_equal(4,body.status)
        
        body.status_getpass!
        assert_equal(true,body.status_getpass?)
        assert_equal(5,body.status)
        
        body.status_restart!
        assert_equal(true,body.status_restart?)
        assert_equal(6,body.status)
        
        body.status_error!
        assert_equal(true,body.status_error?)
        assert_equal(7,body.status)
        
        body.status_follow!
        assert_equal(true,body.status_follow?)
        assert_equal(0x21,body.status)           
    end
    
    def test_reply_flags
        body = TacacsPlus::AuthenticationReply.new
        flag = 0
        
        # toggle flags on
        body.flag_noecho!
        flag = flag | TacacsPlus::AuthenticationReply::TAC_PLUS_REPLY_FLAG_NOECHO
        assert_equal(true,body.flag_noecho?)
        assert_equal(flag,body.flags)
        
        # toggle flags off
        body.flag_noecho!
        flag = flag & (~TacacsPlus::AuthenticationReply::TAC_PLUS_REPLY_FLAG_NOECHO)
        assert_equal(false,body.flag_noecho?)
        assert_equal(flag,body.flags)      
    end
    
    def test_reply_packed
        body = TacacsPlus::AuthenticationReply.new
        assert_kind_of(String,body.packed)
        
        assert_equal(6,body.packed.length)

        body.server_msg = 'A' * (2**16-1)
        body.data = 'A' * (2**16-1)
        
        assert_equal(131076,body.packed.length)        
    end 
    
    def test_reply_print
        body = TacacsPlus::AuthenticationReply.new
        assert_kind_of(String,body.print)
    end
    
    def test_reply_set_len
        body = TacacsPlus::AuthenticationReply.new
        body.server_msg = 'test'
        body.data = 'test'
        body.set_len!
        assert_equal(4,body.server_msg_len)
        assert_equal(4,body.data_len)
    end
    
    
    
    # continue
    def test_continue_new
        body = TacacsPlus::AuthenticationContinue.new
        body.flags = 1
        body.user_msg_len = 4
        body.data_len = 4
        body.user_msg = 'test'
        body.data = 'test'
        
        body2 = TacacsPlus::AuthenticationContinue.new(body.packed)
        assert_not_nil(body2)
        assert_equal(body2.flags,body.flags)
        assert_equal(body2.user_msg_len,body.user_msg_len)
        assert_equal(body2.data_len,body.data_len)
        assert_equal(body2.user_msg,body.user_msg)
        assert_equal(body2.data,body.data)
        
        assert_raise(ArgumentError){TacacsPlus::AuthenticationContinue.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AuthenticationContinue.new('A' * 131076)}
    end    
  
    def test_continue_flags
        body = TacacsPlus::AuthenticationContinue.new
        flag = 0
        
        # toggle flags on
        body.flag_abort!
        flag = flag | TacacsPlus::AuthenticationContinue::TAC_PLUS_CONTINUE_FLAG_ABORT
        assert_equal(true,body.flag_abort?)
        assert_equal(flag,body.flags)
        
        # toggle flags off
        body.flag_abort!
        flag = flag & (~TacacsPlus::AuthenticationContinue::TAC_PLUS_CONTINUE_FLAG_ABORT)
        assert_equal(false,body.flag_abort?)
        assert_equal(flag,body.flags)      
    end
    
    def test_continue_packed
        body = TacacsPlus::AuthenticationContinue.new
        assert_kind_of(String,body.packed)
        
        assert_equal(5,body.packed.length)

        body.user_msg = 'A' * (2**16-1)
        body.data = 'A' * (2**16-1)
        
        assert_equal(131075,body.packed.length)        
    end
    
    def test_continue_print
        body = TacacsPlus::AuthenticationContinue.new
        assert_kind_of(String,body.print)
    end
    
    def test_continue_set_len
        body = TacacsPlus::AuthenticationContinue.new
        body.user_msg = 'test'
        body.data = 'test'
        body.set_len!
        assert_equal(4,body.user_msg_len)
        assert_equal(4,body.data_len)
    end
    
end
