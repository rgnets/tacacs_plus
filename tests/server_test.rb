#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'



class TestServer < Test::Unit::TestCase

    def setup
        @config = YAML.load_file('tests/server_config.yaml')
        @key = @config[:tacacs_daemon][:key]
        @max_pkt = TacacsPlus::TacacsBody::AUTHORIZATION_RESPONSE_MAX_SIZE + TacacsPlus::TacacsHeader::TACACS_HEADER_SIZE


        # load yaml files for pre-recorded server conversation
        @dialogs = {}
        @categories = ["dialogs/malformed_packets", "dialogs/authentication", "dialogs/authorization", "dialogs/cisco_captures"]
        @categories.each do |dir|
            @dialogs[dir] = {}
            Dir.glob("#{dir}/*.yaml").each do |file|
                @dialogs[dir][file] = YAML.load_file(file)
            end
        end

    end

    def test_server_dialog
        @categories.each do |dir|
            puts "\nCategory: #{dir}"
            @dialogs[dir].each_key do |filename|
                 ip = '127.0.0.1'
                 ip = @dialogs[dir][filename][:ip] if (@dialogs[dir][filename].has_key?(:ip))
                 puts "   Dialog: #{filename}:\n" +
                      "           #{@dialogs[dir][filename][:description]}\n"

                # populate arrays with pre-defined data from client/server dialogs.
                client_requests = []
                server_responses = []
                @dialogs[dir][filename][:client_dialog].each {|x| client_requests.push( TacacsPlus.encode_packet(x,@key) )}
                @dialogs[dir][filename][:server_dialog].each {|x| server_responses.push( TacacsPlus.encode_packet(x,@key) )}

                # prepare for client/server dialog.
                logger = TacacsPlus::TestLogger.new
                config = @config.dup
                config[:tacacs_daemon] = @dialogs[dir][filename][:tacacs_daemon] if (@dialogs[dir][filename].has_key?(:tacacs_daemon))
                config[:tacacs_daemon][:logger] = logger
                socket = TacacsPlus::TestIO.new(client_requests)
                tac_server = TacacsPlus::Server.new(config)
                tac_server.test(socket,ip)
                actual_server_responses = socket.write_data

                # perform packet by packet inspection if actual server output has same
                # number of packets as expected server output
                if (server_responses.length == actual_server_responses.length)
                    packet_num = 1
                    server_responses.each do |expected|
                        actual = actual_server_responses.shift
                        if (actual != expected)
                            begin
                                header = TacacsPlus::TacacsHeader.new( actual.slice!(0..11) )
                                actual_dec = TacacsPlus.decode_packet(header,actual,@key)
                                header = TacacsPlus::TacacsHeader.new( expected.slice!(0..11) )
                                expected_dec = TacacsPlus.decode_packet(header,expected,@key)
                            rescue Exception => error
                                raise "Error with server response on packet number #{packet_num} of dialog '#{filename}' : #{error}\n\n"
                            end

                            flunk("\nResponse from server on packet number #{packet_num} of dialog '#{filename}' " +
                                  "did not match what was expected:\n\n" +
                                  "Expected:\n#{expected_dec.to_yaml}\n\nReceived:\n#{actual_dec.to_yaml}\n\n")
                        end

                        packet_num += 1
                    end

                else
                    puts "\nACTUAL RESPONSE\n"
                    actual_server_responses.each {|actual|
                        header = TacacsPlus::TacacsHeader.new( actual.slice!(0..11) )
                        actual_dec = TacacsPlus.decode_packet(header,actual,@key)
                        puts actual_dec.to_yaml + "\n"
                    }
                    puts "\nLOG\n"
                    puts logger.messages.to_yaml
                    puts "\n"
                    flunk("\n Error on '#{filename}': Expected #{server_responses.length} packets from server but received #{actual_server_responses.length}.")
                end

                # test logger output
                logger.messages.pop if (logger.messages.last =~ /Peer sent EOF/)
                if (@dialogs[dir][filename][:server_log] != logger.messages)
                    flunk("\nLogging ouput did not match what was expected for dialog '#{filename}.\n" +
                          "Expected:\n#{@dialogs[dir][filename][:server_log].to_yaml}\n\nReceived:\n#{logger.messages.to_yaml}\n\n")
                end

            end
            print "\n"
        end
    end




end
