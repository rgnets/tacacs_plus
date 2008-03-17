#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestMethods < Test::Unit::TestCase

    def test_encode_decode
        # check that we get the proper kind of packets back from a decode

        key = 'testkey'
        header = TacacsPlus::TacacsHeader.new
        header.type_authentication!
        bodies = [TacacsPlus::AuthenticationStart.new,TacacsPlus::AuthenticationReply.new,
                  TacacsPlus::AuthenticationContinue.new]

        bodies.each do |x|
            pkt = TacacsPlus::PacketStruct.new(header,x)
            pkt.body.set_len!
            pkt.header.length = pkt.body.packed.length
            encoded = TacacsPlus.encode_packet(pkt, key)
            dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
            decoded = TacacsPlus.decode_packet(dec_hdr,encoded,key)

            assert_kind_of(TacacsPlus::TacacsHeader,decoded.header)
            assert_equal(true,header.type_authentication?)
            assert_equal(x.class,decoded.body.class)
            header.inc_seq_no!
        end

        header.reset!
        header.type_authorization!
        bodies = [TacacsPlus::AuthorizationRequest.new,
                  TacacsPlus::AuthorizationResponse.new]

        bodies.each do |x|
            pkt = TacacsPlus::PacketStruct.new(header,x)
            pkt.body.set_len!
            pkt.header.length = pkt.body.packed.length
            encoded = TacacsPlus.encode_packet(pkt,key)
            dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
            decoded = TacacsPlus.decode_packet(dec_hdr,encoded,key)

            assert_kind_of(TacacsPlus::TacacsHeader,decoded.header)
            assert_equal(true,decoded.header.type_authorization?)
            assert_equal(x.class,decoded.body.class)
            header.inc_seq_no!
        end

        header.reset!
        header.type_accounting!
        bodies = [TacacsPlus::AccountingRequest.new,
                  TacacsPlus::AccountingReply.new]

        bodies.each do |x|
            pkt = TacacsPlus::PacketStruct.new(header,x)
            pkt.body.set_len!
            pkt.header.length = pkt.body.packed.length
            encoded = TacacsPlus.encode_packet(pkt,key)
            dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
            decoded = TacacsPlus.decode_packet(dec_hdr,encoded,key)

            assert_kind_of(TacacsPlus::TacacsHeader,decoded.header)
            assert_equal(true,decoded.header.type_accounting?)
            assert_equal(x.class,decoded.body.class)
            header.inc_seq_no!
        end
    end

    def test_encode_decode_fail
        # check for failures when key missing

        key = 'testkey'
        header = TacacsPlus::TacacsHeader.new
        header.type_authentication!
        body = TacacsPlus::AuthenticationStart.new
        pkt_str = TacacsPlus::PacketStruct.new(header,body)
        pkt_str.body.set_len!
        pkt_str.header.length = pkt_str.body.packed.length

        assert_raise(TacacsPlus::EncodeError) {TacacsPlus.encode_packet(pkt_str.dup)}

        encoded = TacacsPlus.encode_packet(pkt_str.dup,key)
        dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
        assert_raise(TacacsPlus::DecodeError) {TacacsPlus.decode_packet(dec_hdr,encoded)}

        pkt_str.header.flag_unencrypted!
        assert_nothing_raised(Exception){TacacsPlus.encode_packet(pkt_str.dup)}

        encoded = TacacsPlus.encode_packet(pkt_str)
        dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
        assert_nothing_raised(Exception){TacacsPlus.decode_packet(dec_hdr,encoded)}
    end

    def test_encode_decode_data_validity
        # check that decoded data matches what we encoded

        key = 'testkey'
        header = TacacsPlus::TacacsHeader.new

        body = TacacsPlus::AuthenticationStart.new
        body.action = 1
        body.priv_lvl = 1
        body.authen_type = 1
        body.service = 1
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.data = 'test'
        body.set_len!
        header.length = body.packed.length
        header.type_authentication!
        pkt_str = TacacsPlus::PacketStruct.new(header,body)
        pkt_str.body.set_len!
        pkt_str.header.length = pkt_str.body.packed.length

        encoded = TacacsPlus.encode_packet(pkt_str,key)
        dec_hdr = TacacsPlus::TacacsHeader.new( encoded.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,encoded,key)

        assert_kind_of(TacacsPlus::AuthenticationStart, decoded.body)
        assert_equal(decoded.body.action,body.action)
        assert_equal(decoded.body.priv_lvl,body.priv_lvl)
        assert_equal(decoded.body.authen_type,body.authen_type)
        assert_equal(decoded.body.service,body.service)
        assert_equal(decoded.body.user,body.user)
        assert_equal(decoded.body.port,body.port)
        assert_equal(decoded.body.rem_addr,body.rem_addr)
        assert_equal(decoded.body.data,body.data)
        assert_equal(decoded.body.user_len,body.user_len)
        assert_equal(decoded.body.port_len,body.port_len)
        assert_equal(decoded.body.rem_addr_len,body.rem_addr_len)
        assert_equal(decoded.body.data_len,body.data_len)

        header.reset!
        header.seq_no = 2
        body = TacacsPlus::AuthenticationReply.new
        body.status = 1
        body.flags = 1
        body.server_msg = 'test'
        body.data = 'test'
        body.set_len!
        header.length = body.packed.length
        header.type_authentication!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AuthenticationReply, decoded.body)
        assert_equal(decoded.body.status,body.status)
        assert_equal(decoded.body.flags,body.flags)
        assert_equal(decoded.body.server_msg,body.server_msg)
        assert_equal(decoded.body.data,body.data)
        assert_equal(decoded.body.server_msg_len,body.server_msg_len)
        assert_equal(decoded.body.data_len,body.data_len)

        header.reset!
        header.seq_no = 3
        body = TacacsPlus::AuthenticationContinue.new
        body.user_msg = 'test'
        body.flags = 1
        body.data = 'test'
        body.set_len!
        header.length = body.packed.length
        header.type_authentication!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AuthenticationContinue, decoded.body)
        assert_equal(decoded.body.flags, body.flags)
        assert_equal(decoded.body.user_msg_len, body.user_msg_len)
        assert_equal(decoded.body.data_len, body.data_len)
        assert_equal(decoded.body.user_msg, body.user_msg)
        assert_equal(decoded.body.data, body.data)

        header.reset!
        body = TacacsPlus::AuthorizationRequest.new
        body.authen_method = 1
        body.priv_lvl = 1
        body.authen_type = 1
        body.authen_service = 1
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.args = ['test','test']
        body.set_len!
        header.length = body.packed.length
        header.type_authorization!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AuthorizationRequest, decoded.body)
        assert_equal(decoded.body.authen_method,body.authen_method)
        assert_equal(decoded.body.priv_lvl,body.priv_lvl)
        assert_equal(decoded.body.authen_type,body.authen_type)
        assert_equal(decoded.body.authen_service,body.authen_service)
        assert_equal(decoded.body.user_len,body.user_len)
        assert_equal(decoded.body.port_len,body.port_len)
        assert_equal(decoded.body.rem_addr_len,body.rem_addr_len)
        assert_equal(decoded.body.arg_cnt,body.arg_cnt)
        assert_equal(decoded.body.arg_lens,body.arg_lens)
        assert_equal(decoded.body.user,body.user)
        assert_equal(decoded.body.port,body.port)
        assert_equal(decoded.body.rem_addr,body.rem_addr)
        assert_equal(decoded.body.args,body.args)

        header.reset!
        header.seq_no = 2
        body = TacacsPlus::AuthorizationResponse.new
        body.status = 1
        body.args = ['test','test']
        body.server_msg = 'test'
        body.data = 'test'
        body.set_len!
        header.length = body.packed.length
        header.type_authorization!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AuthorizationResponse, decoded.body)
        assert_equal(decoded.body.status, body.status)
        assert_equal(decoded.body.arg_cnt, body.arg_cnt)
        assert_equal(decoded.body.arg_lens, body.arg_lens)
        assert_equal(decoded.body.args, body.args)
        assert_equal(decoded.body.server_msg, body.server_msg)
        assert_equal(decoded.body.data, body.data)
        assert_equal(decoded.body.server_msg_len, body.server_msg_len)
        assert_equal(decoded.body.data_len, body.data_len)

        header.reset!
        body = TacacsPlus::AccountingRequest.new
        body.flags = 1
        body.authen_method = 1
        body.priv_lvl = 1
        body.authen_type = 1
        body.authen_service = 1
        body.user = 'test'
        body.port = 'test'
        body.rem_addr = 'test'
        body.args = ['test','test']
        body.set_len!
        header.length = body.packed.length
        header.type_accounting!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AccountingRequest, decoded.body)
        assert_equal(decoded.body.flags,body.flags)
        assert_equal(decoded.body.authen_method,body.authen_method)
        assert_equal(decoded.body.priv_lvl,body.priv_lvl)
        assert_equal(decoded.body.authen_type,body.authen_type)
        assert_equal(decoded.body.authen_service,body.authen_service)
        assert_equal(decoded.body.user_len,body.user_len)
        assert_equal(decoded.body.port_len,body.port_len)
        assert_equal(decoded.body.rem_addr_len,body.rem_addr_len)
        assert_equal(decoded.body.arg_cnt,body.arg_cnt)
        assert_equal(decoded.body.arg_lens,body.arg_lens)
        assert_equal(decoded.body.user,body.user)
        assert_equal(decoded.body.port,body.port)
        assert_equal(decoded.body.rem_addr,body.rem_addr)
        assert_equal(decoded.body.args,body.args)

        header.reset!
        header.seq_no = 2
        body = TacacsPlus::AccountingReply.new
        body.server_msg
        body.data
        body.status
        body.set_len!
        header.length = body.packed.length
        header.type_accounting!

        pkt = TacacsPlus.encode_packet(TacacsPlus::PacketStruct.new(header,body),key)
        dec_hdr = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
        decoded = TacacsPlus.decode_packet(dec_hdr,pkt,key)

        assert_kind_of(TacacsPlus::AccountingReply, decoded.body) 
        assert_equal(decoded.body.status, body.status)
        assert_equal(decoded.body.server_msg, body.server_msg)
        assert_equal(decoded.body.data, body.data)
        assert_equal(decoded.body.server_msg_len, body.server_msg_len)
        assert_equal(decoded.body.data_len, body.data_len)
    end

end
