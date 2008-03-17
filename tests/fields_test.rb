#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestFields < Test::Unit::TestCase
    
    def test_action
        bodies = [TacacsPlus::AuthenticationStart.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.action)
        
            body.action = 65
            assert_equal(65,body.action)
        
            body.action = 65.chr
            assert_equal(65,body.action)
            
            body.action_chpass!
            assert_equal(true,body.action_chpass?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_CHPASS,body.action)
        
            body.action_login!
            assert_equal(true,body.action_login?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_LOGIN,body.action)
        
            body.action_sendauth!
            assert_equal(true,body.action_sendauth?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SENDAUTH,body.action)
        
            body.action_sendpass!
            assert_equal(true,body.action_sendpass?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SENDPASS,body.action)            
        end
    end
    
    def test_args
        bodies = [TacacsPlus::AuthorizationRequest.new, TacacsPlus::AuthorizationResponse.new,
                  TacacsPlus::AccountingRequest.new]
        
        avpairs = ['cmd=show', 'cmd=ip', 'cmd-arg=ip route', 'cmd-arg=route 0.0.0.0 0.0.0.0 1.1.1.1']
        
        bodies.each do |body|
            assert_nothing_raised(Exception){body.args=(['abcd','efgh'])}
            assert_nothing_raised(Exception){body.arg_lens=([4,'A'])}
            
            assert_raise(ArgumentError){body.args=(['abcd',1])}
            assert_raise(ArgumentError){body.arg_lens=(['AA',4])}
            
            body.arg_cnt = 65
            assert_equal(65,body.arg_cnt)
        
            body.arg_cnt = 65.chr
            assert_equal(65,body.arg_cnt)
        end
    end
    
    def test_authen_method
        bodies = [TacacsPlus::AuthorizationRequest.new, TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.authen_method)
        
            body.authen_method = 65
            assert_equal(65,body.authen_method)
        
            body.authen_method = 65.chr
            assert_equal(65,body.authen_method)
            
            body.authen_method_notset!
            assert_equal(true,body.authen_method_notset?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_NOT_SET,body.authen_method)
            
            body.authen_method_none!
            assert_equal(true,body.authen_method_none?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_NONE,body.authen_method)
            
            body.authen_method_krb5!
            assert_equal(true,body.authen_method_krb5?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_KRB5,body.authen_method)
            
            body.authen_method_line!
            assert_equal(true,body.authen_method_line?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_LINE,body.authen_method)
            
            body.authen_method_enable!
            assert_equal(true,body.authen_method_enable?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_ENABLE,body.authen_method)
            
            body.authen_method_local!
            assert_equal(true,body.authen_method_local?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_LOCAL,body.authen_method)
            
            body.authen_method_tacacsplus!
            assert_equal(true,body.authen_method_tacacsplus?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_TACACSPLUS,body.authen_method)
            
            body.authen_method_guest!
            assert_equal(true,body.authen_method_guest?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_GUEST,body.authen_method)
            
            body.authen_method_radius!
            assert_equal(true,body.authen_method_radius?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_RADIUS,body.authen_method)
            
            body.authen_method_krb4!
            assert_equal(true,body.authen_method_krb4?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_KRB4,body.authen_method)
            
            body.authen_method_rcmd!
            assert_equal(true,body.authen_method_rcmd?)
            assert_equal(TacacsPlus::AuthenMethod::TAC_PLUS_AUTHEN_METH_RCMD,body.authen_method)          
        end
    end
    
    def test_service
        bodies = [TacacsPlus::AuthorizationRequest.new, TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.service)
        
            body.service = 65
            assert_equal(65,body.service)
        
            body.service = 65.chr
            assert_equal(65,body.service)
            
            body.service_none!
            assert_equal(true,body.service_none?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_NONE,body.service)
        
            body.service_login!
            assert_equal(true,body.service_login?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_LOGIN,body.service)
        
            body.service_enable!
            assert_equal(true,body.service_enable?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_ENABLE,body.service)
        
            body.service_ppp!
            assert_equal(true,body.service_ppp?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_PPP,body.service)
        
            body.service_arap!
            assert_equal(true,body.service_arap?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_ARAP,body.service)
        
            body.service_pt!
            assert_equal(true,body.service_pt?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_PT,body.service)
        
            body.service_rcmd!
            assert_equal(true,body.service_rcmd?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_RCMD,body.service)
        
            body.service_x25!
            assert_equal(true,body.service_x25?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_X25,body.service)
        
            body.service_nasi!
            assert_equal(true,body.service_nasi?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_NASI,body.service)
        
            body.service_fwproxy!
            assert_equal(true,body.service_fwproxy?)
            assert_equal(TacacsPlus::AuthenticationStart::TAC_PLUS_AUTHEN_SVC_FWPROXY,body.service)            
        end
    end
    
    def test_authen_type
        bodies = [TacacsPlus::AuthenticationStart.new, TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.authen_type)
        
            body.authen_type = 65
            assert_equal(65,body.authen_type)
        
            body.authen_type = 65.chr
            assert_equal(65,body.authen_type)
            
            body.authen_type_ascii!
            assert_equal(true,body.authen_type_ascii?)
            assert_equal(1,body.authen_type)
        
            body.authen_type_pap!
            assert_equal(true,body.authen_type_pap?)
            assert_equal(2,body.authen_type)
        
            body.authen_type_chap!
            assert_equal(true,body.authen_type_chap?)
            assert_equal(3,body.authen_type)
        
            body.authen_type_arap!
            assert_equal(true,body.authen_type_arap?)
            assert_equal(4,body.authen_type)
        
            body.authen_type_mschap!
            assert_equal(true,body.authen_type_mschap?)
            assert_equal(5,body.authen_type)
        end
    end
    
    def test_data
        bodies = {TacacsPlus::AuthenticationStart.new => 1, TacacsPlus::AuthenticationReply.new => 2,
                  TacacsPlus::AuthenticationContinue.new => 2,
                  TacacsPlus::AuthorizationResponse.new => 2, TacacsPlus::AccountingReply.new => 2}
        
        bodies.each_key do |body|
            byte_len = bodies[body]
            
            assert_kind_of(Integer,body.data_len)
        
            body.data_len = 65
            assert_equal(65,body.data_len)        
        
            body.data = 'test'

            assert_kind_of(String,body.data)
            assert_equal(4,body.data.length)
        
            body.data = 'A' * 255
            assert_equal(('A' * 255),body.data)
        end
    end
    
    def test_flags
        bodies = [TacacsPlus::AuthenticationReply.new, TacacsPlus::AuthenticationContinue.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.flags)
        
            body.flags = 65
            assert_equal(65,body.flags)
        
            body.flags = 65.chr
            assert_equal(65,body.flags)
            body.flags_clear!
            
            assert_equal(0,body.flags)
        end
    end
    
    def test_major_ver
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|        
            assert_kind_of(Integer,body.major_version)
            assert_equal(0xc,body.major_version)
            body.version = 128
            assert_equal(8,body.major_version)
            body.major_version = 15
            assert_equal(240,body.version)
        end
    end
    
    def test_minor_ver
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|       
            assert_kind_of(Integer,body.minor_version)
            assert_equal(0,body.minor_version)
            body.minor_version = 1
            assert_equal(1,body.minor_version)
            body.version = 4
            assert_equal(4,body.minor_version)
            body.reset!
            body.minor_version = 15
            assert_equal(207,body.version)
        end        
    end
    
    def test_version
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|
        
            assert_kind_of(Integer,body.version)
        
            body.version = 65
            assert_equal(65,body.version)
        
            body.version = 65.chr
            assert_equal(65,body.version)
        end                
    end
    
    def test_type
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|
        
            assert_kind_of(Integer,body.type)
        
            body.type = 100
            assert_equal(100,body.type)
        
            body.type_accounting!
            assert_equal(true,body.type_accounting?)
            body.type_authentication!
            assert_equal(true,body.type_authentication?)
            body.type_authorization!
            assert_equal(true,body.type_authorization?)
        
            body.type = 65.chr
            assert_equal(65,body.type)
        end                      
    end
    
    def test_seq_no
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|        
            assert_kind_of(Integer,body.seq_no)
        
            body.seq_no = 5
            assert_equal(5,body.seq_no)
        
            body.inc_seq_no!
            assert_equal(6,body.seq_no)
            body.dec_seq_no!
            assert_equal(5,body.seq_no)
        
            body.seq_no = 65.chr
            assert_equal(65,body.seq_no)
        end                
    end

    def test_session_id
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|        
            assert_kind_of(Integer,body.session_id)
        
            body.session_id = 1
            assert_equal(1,body.session_id)
        
            body.randomize_session_id!
        
            body.session_id = 'AAAA'
            assert_equal('AAAA'.unpack('N')[0],body.session_id)
        end               
    end
    
    def test_length
        bodies = [TacacsPlus::TacacsHeader.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.length)
        
            body.length = 1
            assert_equal(1,body.length)
        
            body.length = 'AAAA'
            assert_equal('AAAA'.unpack('N')[0],body.length) 
        end               
    end
    
    def test_port
        bodies = [TacacsPlus::AuthenticationStart.new, TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.port_len)
        
            body.port_len = 65
            assert_equal(65,body.port_len)
        
            body.port_len = 65.chr
            assert_equal(65,body.port_len)
            
            body.port = 'test'

            assert_kind_of(String,body.port)
            assert_equal(4,body.port.length)
        
            body.port = 'A' * 255
            assert_equal(('A' * 255),body.port)
        end
    end
    
    def test_priv_lvl
        bodies = [TacacsPlus::AuthenticationStart.new, TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.priv_lvl)
        
            body.priv_lvl = 65
            assert_equal(65,body.priv_lvl)
        
            body.priv_lvl = 65.chr
            assert_equal(65,body.priv_lvl)
        end
    end
    
    def test_rem_addr
        bodies = [TacacsPlus::AuthenticationStart.new, TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.rem_addr_len)
        
            body.rem_addr_len = 65
            assert_equal(65,body.rem_addr_len)
        
            body.rem_addr_len = 65.chr
            assert_equal(65,body.rem_addr_len)
        
            body.rem_addr = 'test'

            assert_kind_of(String,body.rem_addr)
            assert_equal(4,body.rem_addr.length)
        
            body.rem_addr = 'A' * 255
            assert_equal(('A' * 255),body.rem_addr)
        end
    end
    
    def test_server_msg
        bodies = [TacacsPlus::AuthenticationReply.new, TacacsPlus::AuthorizationResponse.new,
                  TacacsPlus::AccountingReply.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.server_msg_len)
        
            body.server_msg_len = 65
            assert_equal(65,body.server_msg_len)
        
            body.server_msg_len = 'AA'
            assert_equal('AA'.unpack('n')[0],body.server_msg_len)
              
            body.server_msg = 'test'

            assert_kind_of(String,body.server_msg)
            assert_equal(4,body.server_msg.length)
        
            body.server_msg = 'A' * (2**16-1)
            assert_equal(('A' * (2**16-1)),body.server_msg)
        end
    end
    
    def test_service
        bodies = [TacacsPlus::AuthenticationStart.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.service)
        
            body.service = 65
            assert_equal(65,body.service)
        
            body.service = 65.chr
            assert_equal(65,body.service)
        end
    end
    
    def test_status
        bodies = [TacacsPlus::AuthenticationReply.new, TacacsPlus::AuthorizationResponse.new,
                  TacacsPlus::AccountingReply.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.status)
        
            body.status = 65
            assert_equal(65,body.status)
        
            body.status = 65.chr
            assert_equal(65,body.status)
        end
    end
    
    def test_user
        bodies = [TacacsPlus::AuthenticationStart.new, TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AccountingRequest.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.user_len)
        
            body.user_len = 65
            assert_equal(65,body.user_len)
        
            body.user_len = 65.chr
            assert_equal(65,body.user_len)
            
            body.user = 'test'

            assert_kind_of(String,body.user)
            assert_equal(4,body.user.length)
        
            body.user = 'A' * 255
            assert_equal(('A' * 255),body.user)
        end
    end
    
    def test_user_msg
        bodies = [TacacsPlus::AuthenticationContinue.new]
        
        bodies.each do |body|
            assert_kind_of(Integer,body.user_msg_len)
        
            body.user_msg_len = 65
            assert_equal(65,body.user_msg_len)
        
            body.user_msg_len = 'AA'
            assert_equal('AA'.unpack('n')[0],body.user_msg_len)
            
           body.user_msg = 'test'

           assert_kind_of(String,body.user_msg)
           assert_equal(4,body.user_msg.length)
        
           body.user_msg = 'A' * (2**16-1)
           assert_equal(('A' * (2**16-1)),body.user_msg) 
        end
    end
    

end
