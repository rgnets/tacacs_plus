#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestAccounting < Test::Unit::TestCase

    def test_request_new
        body = TacacsPlus::AccountingRequest.new
        assert_not_nil(body)
        
        body.flags = 1
        body.authen_method = 1
        body.priv_lvl = 1
        body.authen_type = 1
        body.authen_service = 1
        body.user_len = 4
        body.port_len = 4
        body.rem_addr_len = 4
        body.arg_cnt = 2
        body.arg_lens = [4,4]
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.args = ['test','test']
        
        body2 = TacacsPlus::AccountingRequest.new(body.packed)
        assert_not_nil(body2)
        
        assert_equal(body2.flags,body.flags)
        assert_equal(body2.authen_method,body.authen_method)
        assert_equal(body2.priv_lvl,body.priv_lvl)
        assert_equal(body2.authen_type,body.authen_type)
        assert_equal(body2.authen_service,body.authen_service)
        assert_equal(body2.user_len,body.user_len)
        assert_equal(body2.port_len,body.port_len)
        assert_equal(body2.rem_addr_len,body.rem_addr_len)
        assert_equal(body2.arg_cnt,body.arg_cnt)
        assert_equal(body2.arg_lens,body.arg_lens)
        assert_equal(body2.user,body.user)
        assert_equal(body2.port,body.port)
        assert_equal(body2.rem_addr,body.rem_addr)
        assert_equal(body2.args,body.args)
        
        assert_raise(ArgumentError){TacacsPlus::AccountingRequest.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AccountingRequest.new('A' * 66311)}
    end
    
    def test_request_flags
        body = TacacsPlus::AccountingRequest.new
        flag = 0
        
        # toggle flags on
        body.flag_more!
        flag = flag | TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_MORE
        assert_equal(true,body.flag_more?)
        assert_equal(flag,body.flags)
        
        body.flag_start!
        flag = flag | TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_START
        assert_equal(true,body.flag_start?)
        assert_equal(flag,body.flags)
        
        body.flag_stop!
        flag = flag | TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_STOP
        assert_equal(true,body.flag_stop?)
        assert_equal(flag,body.flags)
        
        body.flag_watchdog!
        flag = flag | TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_WATCHDOG
        assert_equal(true,body.flag_watchdog?)
        assert_equal(flag,body.flags)
        
        # toggle flags off
        body.flag_more!
        flag = flag & (~TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_MORE)
        assert_equal(false,body.flag_more?)
        assert_equal(flag,body.flags)
        
        body.flag_start!
        flag = flag & (~TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_START)
        assert_equal(false,body.flag_start?)
        assert_equal(flag,body.flags)
        
        body.flag_stop!
        flag = flag & (~TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_STOP)
        assert_equal(false,body.flag_stop?)
        assert_equal(flag,body.flags)
        
        body.flag_watchdog!
        flag = flag & (~TacacsPlus::AccountingRequest::TAC_PLUS_ACCT_FLAG_WATCHDOG)
        assert_equal(false,body.flag_watchdog?)
        assert_equal(flag,body.flags)             
    end
    
    def test_request_packed
        body = TacacsPlus::AccountingRequest.new
        assert_kind_of(String,body.packed)
        
        assert_equal(9,body.packed.length)
        
        body.user = 'A' * 255
        body.port = 'A' * 255
        body.rem_addr = 'A' * 255
        
        assert_equal(774,body.packed.length)        
    end
    
    def test_request_print
        body = TacacsPlus::AccountingRequest.new
        assert_kind_of(String,body.print)
    end
    
    def test_request_set_len
        body = TacacsPlus::AccountingRequest.new
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.set_len!
        assert_equal(4,body.user_len)
        assert_equal(4,body.port_len)
        assert_equal(4,body.rem_addr_len)
    end
    
    
    # reply
    def test_reply_new
        body = TacacsPlus::AccountingReply.new
        body.server_msg_len = 4
        body.data_len = 4
        body.status = 1
        body.server_msg = 'test'
        body.data = 'test'
        
        body2 = TacacsPlus::AccountingReply.new(body.packed)
        assert_not_nil(body2)
        
        assert_equal(body2.server_msg_len,body.server_msg_len)
        assert_equal(body2.data_len,body.data_len)
        assert_equal(body2.status,body.status)
        assert_equal(body2.server_msg,body.server_msg)
        assert_equal(body2.data,body.data)
        
        assert_raise(ArgumentError){TacacsPlus::AccountingReply.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AccountingReply.new('A' * 131076)}
    end
    
    def test_reply_packed
        body = TacacsPlus::AccountingReply.new
        assert_kind_of(String,body.packed)
        
        assert_equal(5,body.packed.length)

        body.server_msg = 'A' * 65535
        body.data = 'A' * 65535
        
        assert_equal(131075,body.packed.length)        
    end
    
    def test_reply_print
        body = TacacsPlus::AccountingReply.new
        assert_kind_of(String,body.print)
    end
    
    def test_reply_set_len
        body = TacacsPlus::AccountingReply.new
        body.server_msg = 'test'
        body.data = 'test'
        body.set_len!
        assert_equal(4,body.server_msg_len)
        assert_equal(4,body.data_len)
    end
    
    def test_reply_status
        body = TacacsPlus::AccountingReply.new
        
        body.status_success!
        assert_equal(true,body.status_success?)
        assert_equal(TacacsPlus::AccountingReply::TAC_PLUS_ACCT_STATUS_SUCCESS,body.status)
        
        body.status_error!
        assert_equal(true,body.status_error?)
        assert_equal(TacacsPlus::AccountingReply::TAC_PLUS_ACCT_STATUS_ERROR,body.status)
        
        body.status_follow!
        assert_equal(true,body.status_follow?)
        assert_equal(TacacsPlus::AccountingReply::TAC_PLUS_ACCT_STATUS_FOLLOW,body.status)              
    end

end
