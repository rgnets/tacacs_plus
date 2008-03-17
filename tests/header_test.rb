#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestHeader < Test::Unit::TestCase

    def test_new
        header = TacacsPlus::TacacsHeader.new
        assert_not_nil(header)
        
        header.type = 1
        header.seq_no = 1
        header.flags = 1
        header.session_id = 1
        header.length = 1        
        
        header2 = TacacsPlus::TacacsHeader.new(header.packed)
        assert_not_nil(header2)
        
        assert_equal(header2.version,header.version)
        assert_equal(header2.type,header.type)
        assert_equal(header2.seq_no,header.seq_no)
        assert_equal(header2.flags,header.flags)
        assert_equal(header2.length,header.length)        
    end
    
    
    def test_flags
        header = TacacsPlus::TacacsHeader.new
        
        assert_kind_of(Integer,header.flags)
        
        header.flags = 10
        assert_equal(10,header.flags)        
        
        header.flags_clear!
        assert_equal(0,header.flags)
        
        header.flags = 65.chr
        assert_equal(65,header.flags)
        header.flags_clear!
        
        flag = 0
        
        # toggle flags on
        header.flag_unencrypted!
        flag = flag | TacacsPlus::TacacsHeader::TAC_PLUS_UNENCRYPTED_FLAG
        assert_equal(true,header.flag_unencrypted?)
        assert_equal(flag,header.flags)
        
        header.flag_single_connection!
        flag = flag | TacacsPlus::TacacsHeader::TAC_PLUS_SINGLE_CONNECT_FLAG
        assert_equal(true,header.flag_single_connection?)
        assert_equal(flag,header.flags)
        
        # toggle flags off
        header.flag_unencrypted!
        flag = flag & (~TacacsPlus::TacacsHeader::TAC_PLUS_UNENCRYPTED_FLAG)
        assert_equal(false,header.flag_unencrypted?)
        assert_equal(flag,header.flags)
        
        header.flag_single_connection!
        flag = flag & (~TacacsPlus::TacacsHeader::TAC_PLUS_SINGLE_CONNECT_FLAG)
        assert_equal(false,header.flag_single_connection?)
        assert_equal(flag,header.flags)
    end
    
    
    def test_packed
        header = TacacsPlus::TacacsHeader.new        
        assert_kind_of(String,header.packed)        
        assert_equal(12,header.packed.length)
    end
    
    def test_print
        header = TacacsPlus::TacacsHeader.new
        printed = header.print        
        assert_kind_of(String,printed)
    end
    
    def test_reset
        header = TacacsPlus::TacacsHeader.new
        header.major_version = 1
        header.minor_version = 1
        header.type = 1
        header.flags = 1
        header.session_id = 1
        header.seq_no = 1
        header.length = 1
        header.reset!
        
        assert_equal(12, header.major_version)
        assert_equal(0, header.minor_version)
        assert_equal(0, header.type)
        assert_equal(0, header.flags)
        assert_equal(0, header.session_id)
        assert_equal(1, header.seq_no)
        assert_equal(0, header.length)
    end
    
end
