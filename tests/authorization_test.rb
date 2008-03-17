#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestAuthorization < Test::Unit::TestCase

    def test_request_new
        body = TacacsPlus::AuthorizationRequest.new
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
        
        body2 = TacacsPlus::AuthorizationRequest.new(body.packed)
        assert_not_nil(body2)
        
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
        
        assert_raise(ArgumentError){TacacsPlus::AuthorizationRequest.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AuthorizationRequest.new('A' * 66310)}
    end
    
    def test_request_packed
        body = TacacsPlus::AuthorizationRequest.new
        assert_kind_of(String,body.packed)
        
        assert_equal(8,body.packed.length)
        
        body.user = 'A' * 255
        body.port = 'A' * 255
        body.rem_addr = 'A' * 255
        
        assert_equal(773,body.packed.length)        
    end
    
    def test_request_print
        body = TacacsPlus::AuthorizationRequest.new
        assert_kind_of(String,body.print)
    end
    
    def test_request_set_len
        body = TacacsPlus::AuthorizationRequest.new
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.set_len!
        assert_equal(4,body.user_len)
        assert_equal(4,body.port_len)
        assert_equal(4,body.rem_addr_len)
    end
    
    
    
    # response
    def test_response_new
        body = TacacsPlus::AuthorizationResponse.new
        body.status = 1
        body.arg_cnt = 2
        body.server_msg_len = 4
        body.data_len = 4
        body.arg_lens = [4,4]
        body.server_msg = 'test'
        body.data = 'test'
        body.args = ['test','test']
        
        body2 = TacacsPlus::AuthorizationResponse.new(body.packed)
        assert_not_nil(body2)
        
        assert_equal(body2.status,body.status)
        assert_equal(body2.arg_cnt,body.arg_cnt)
        assert_equal(body2.server_msg_len,body.server_msg_len)
        assert_equal(body2.data_len,body.data_len)
        assert_equal(body2.arg_lens,body.arg_lens)
        assert_equal(body2.server_msg,body.server_msg)
        assert_equal(body2.data,body.data)
        assert_equal(body2.args,body.args)
        
        assert_raise(ArgumentError){TacacsPlus::AuthorizationResponse.new('A')}
        assert_raise(ArgumentError){TacacsPlus::AuthorizationResponse.new('A' * 196613)}
    end
    
    def test_response_packed
        body = TacacsPlus::AuthorizationResponse.new
        assert_kind_of(String,body.packed)
        
        assert_equal(6,body.packed.length)

        body.server_msg = 'A' * 65535
        body.data = 'A' * 65535
        
        assert_equal(131076,body.packed.length)        
    end
    
    def test_response_print
        body = TacacsPlus::AuthorizationResponse.new
        assert_kind_of(String,body.print)
    end
    
    def test_response_set_len
        body = TacacsPlus::AuthorizationResponse.new
        body.server_msg = 'test'
        body.data = 'test'
        body.set_len!
        assert_equal(4,body.server_msg_len)
        assert_equal(4,body.data_len)
    end
    
    def test_response_status
        body = TacacsPlus::AuthorizationResponse.new
        
        body.status_passadd!
        assert_equal(true,body.status_passadd?)
        assert_equal(TacacsPlus::AuthorizationResponse::TAC_PLUS_AUTHOR_STATUS_PASS_ADD,body.status)
        
        body.status_passrepl!
        assert_equal(true,body.status_passrepl?)
        assert_equal(TacacsPlus::AuthorizationResponse::TAC_PLUS_AUTHOR_STATUS_PASS_REPL,body.status)
        
        body.status_fail!
        assert_equal(true,body.status_fail?)
        assert_equal(TacacsPlus::AuthorizationResponse::TAC_PLUS_AUTHOR_STATUS_FAIL,body.status)
        
        body.status_error!
        assert_equal(true,body.status_error?)
        assert_equal(TacacsPlus::AuthorizationResponse::TAC_PLUS_AUTHOR_STATUS_ERROR,body.status)
        
        body.status_follow!
        assert_equal(true,body.status_follow?)
        assert_equal(TacacsPlus::AuthorizationResponse::TAC_PLUS_AUTHOR_STATUS_FOLLOW,body.status)              
    end    

end
