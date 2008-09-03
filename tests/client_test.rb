#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestClient < Test::Unit::TestCase

    def setup
        @key = 's0mek3y'
        @client = TacacsPlus::Client.new(:key => @key, :server => '127.0.0.1')
        @config = {:key => 'key', :logger => '/tmp/client.log', :dump_file => '/tmp/dump.log',
                   :port => 49, :server => 'localhost', :session_id => 4949, :testing => false}
    end

    def test_can_create
        assert_nothing_raised(Exception){TacacsPlus::Client.new(@config)}
    end

    def test_key_not_string_error
        config = @config.dup
        config[:key] = 1
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_dump_file_error
        config = @config.dup
        config[:dump_file] = 1
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_port_not_int_error
        config = @config.dup
        config[:port] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_server_not_string_error
        config = @config.dup
        config[:server] = 1
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_session_id_not_string_error
        config = @config.dup
        config[:session_id] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_testing_not_t_or_f_error
        config = @config.dup
        config[:testing] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Client.new(config)}
    end

    def test_accounting_normal1
        file = 'dialogs/accounting/accounting_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.account('dustin', ['task_id=1', 'timezone=cst'], :start => true)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authorization_service_shell_cmd_present_normal1
        file = 'dialogs/authorization/authorization_service_shell_cmd_present_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.authorize_command('dustin', 'show version')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_login_normal1
        file = 'dialogs/authentication/authentication_login_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.login('dustin', 'password')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_login_normal2
        file = 'dialogs/authentication/authentication_login_normal2.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.login('dustin', 'password', true)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_enable_normal1
        file = 'dialogs/authentication/authentication_enable_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.enable('dustin', 'enable')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_enable_normal2
        file = 'dialogs/authentication/authentication_enable_normal2.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.enable('dustin', 'enable', false)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_ascii_chpass_enable_normal1
        file = 'dialogs/authentication/authentication_ascii_chpass_enable_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.change_enable_password('dustin','enable','new_password', false)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_ascii_chpass_enable_normal2
        file = 'dialogs/authentication/authentication_ascii_chpass_enable_normal2.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.change_enable_password('dustin','enable','new_password')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_ascii_chpass_normal1
        file = 'dialogs/authentication/authentication_ascii_chpass_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.change_password('dustin','password','new_password', false)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_ascii_chpass_normal2
        file = 'dialogs/authentication/authentication_ascii_chpass_normal2.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.change_password('dustin','password','new_password')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_chap_login_normal1
        file = 'dialogs/authentication/authentication_chap_login_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.chap_login('dustin', 'password', 'a', 'challenge')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_pap_login_normal1
        file = 'dialogs/authentication/authentication_pap_login_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.pap_login('dustin', 'password')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authentication_abort
        file = 'dialogs/authentication/authentication_abort.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.server_alive?
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_authorization_service_shell_cmd_null_normal1
        file = 'dialogs/authorization/authorization_service_shell_cmd_null_normal1.yaml'
        dialog =  YAML.load_file(file)
        client_requests = setup_client(dialog)
        @client.authorization_avpairs('dustin')
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end

    def test_script_play
        file = 'dialogs/authentication/authentication_login_normal1.yaml'
        dialog =  YAML.load_file(file)
        script =  YAML.load_file(file)[:client_dialog]
        client_requests = setup_client(dialog)
        @client.script_play(script)
        actual_client_requests = @client.socket.write_data
        pkt_inspect(actual_client_requests, client_requests, file)
        log_inspect(@client.logger.messages, dialog[:client_log], file)
    end






    def setup_client(dialog)
        # populate arrays with pre-defined data from client/server dialogs.
        client_requests = []
        server_responses = []
        dialog[:client_dialog].each {|x| client_requests.push( TacacsPlus.encode_packet(x,@key) )}
        dialog[:server_dialog].each {|x| server_responses.push( TacacsPlus.encode_packet(x,@key) )}

        # prepare for client/server dialog.
        @client.logger = TacacsPlus::TestLogger.new
        @client.socket = TacacsPlus::TestIO.new(server_responses)
        @client.session_id = dialog[:client_dialog][0].header.session_id
        return(client_requests)
    end


    def pkt_inspect(actual_client_requests, client_requests, filename)
        # perform packet by packet inspection if actual client requests has same
        # number of packets as expected client requests
        if (client_requests.length == actual_client_requests.length)
            packet_num = 1
            client_requests.each do |expected|
                actual = actual_client_requests.shift
                if (actual != expected)
                    begin
                        hdr = TacacsPlus::TacacsHeader.new( actual.slice!(0..11) )
                        actual_dec = TacacsPlus.decode_packet(hdr,actual,@key)
                        hdr = TacacsPlus::TacacsHeader.new( expected.slice!(0..11) )
                        expected_dec = TacacsPlus.decode_packet(hdr,expected,@key)
                    rescue Exception => error
                        raise "Error with client request on packet number #{packet_num} of dialog '#{filename}' : #{error}\n\n"
                    end

                    flunk("\nRequest from client on packet number #{packet_num} of dialog '#{filename}' " +
                          "did not match what was expected:\n\n" +
                          "Expected:\n#{expected_dec.to_yaml}\n\nReceived:\n#{actual_dec.to_yaml}\n\n")
                end

                packet_num += 1
           end

        else
            flunk("\nExpected #{client_requests.length} packets from client but received #{actual_client_requests.length}.")
        end

    end


    def log_inspect(actual,expected, filename)
        # test logger output
        if (actual != expected)
            flunk("\nLogging ouput did not match what was expected for dialog '#{filename}.\n" +
                  "Expected:\n#{expected.to_yaml}\n\nReceived:\n#{actual.to_yaml}\n\n")
        end
    end

end
