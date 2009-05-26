#!/usr/bin/ruby

require 'lib/tacacs_plus.rb'
require 'test/unit'


class TestServer < Test::Unit::TestCase

    def setup
        @config = YAML.load_file('tests/server_config.yaml')
    end

    def test_can_create
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    # general config parameters
    def test_config_unrecognized_option_error
        config = @config.dup
        config[:option] = true
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_config_not_hash_error
        config = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_config_missing_tacacs_daemon_error
        config = @config.dup
        config.delete(:tacacs_daemon)
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_config_properly_returned
        server = TacacsPlus::Server.new(@config)
        config = server.configuration
        @config[:shell_command_object_groups].each_pair do |k,v|
            if (v != config[:shell_command_object_groups][k])
                puts "\nConfigurations for shell_command_object_group #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:shell_command_object_groups][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        @config[:network_object_groups].each_pair do |k,v|
            if (v != config[:network_object_groups][k])
                puts "\nConfigurations for network_object_group #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:network_object_groups][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        @config[:acls].each_pair do |k,v|
            if (v != config[:acls][k])
                puts "\nConfigurations for acl #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:acls][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        @config[:command_authorization_profiles].each_pair do |k,v|
            if (v != config[:command_authorization_profiles][k])
                puts "\nConfigurations for command_authorization_profile #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:command_authorization_profiles][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        if (@config[:command_authorization_whitelist] != config[:command_authorization_whitelist])
                puts "\ncommand_authorization_whitelists were not equal"
                puts "\n\n#### EXPECTED ####"
                puts @config[:command_authorization_whitelist].to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:command_authorization_whitelist].to_yaml
                puts "\n\n"
                flunk()
        end

        @config[:author_avpairs].each_pair do |k,v|
            if (v != config[:author_avpairs][k])
                puts "\nConfigurations for author_avpair #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:author_avpairs][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        @config[:user_groups].each_pair do |k,v|
            if (v != config[:user_groups][k])
                puts "\nConfigurations for user_group #{k} were not equal."
                puts "\n\n#### EXPECTED ####"
                puts v.to_yaml
                puts "\n\n#### RECEIVED ####"
                puts config[:user_groups][k].to_yaml
                puts "\n\n"
                flunk()
            end
        end

        @config[:users].each_pair do |username,opt|
            opt.each_pair do |opt_name,opt_val|
                if (opt_val != config[:users][username][opt_name])
                    puts "\nConfigurations for user #{k} were not equal."
                    puts "\n\n#### EXPECTED ####"
                    puts v.to_yaml
                    puts "\n\n#### RECEIVED ####"
                    puts config[:users][k].to_yaml
                    puts "\n\n"
                    flunk()
                end
            end
        end
    end



    # shell command object groups
    def test_arg_shell_command_object_groups_structure
        config = @config.dup
        config[:shell_command_object_groups] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:shell_command_object_groups] = {'group1' => {}, 'group2' => {}}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:shell_command_object_groups] = {'show commands' => ['show run', 'show version']}
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    def test_arg_shell_command_object_groups_command_invalid_error
        config = @config.dup
        config[:shell_command_object_groups]['show commands'].push(1)
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:shell_command_object_groups]['show commands'][3] = 'command'
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    # network object groups
    def test_arg_network_object_groups_structure
        config = @config.dup
        config[:network_object_groups] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:network_object_groups] = {'datacenter1' => {}}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:network_object_groups] = {'datacenter1' => [ {:ip => '10.1.0.0', :wildcard_mask => '0.0.255.255'} ] }
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    def test_arg_network_object_groups_ip_invalid_error
        config = @config.dup
        config[:network_object_groups]['datacenter1'].push({:ip => '1.1.1.1.1'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_network_object_groups_ip_missing_error
        config = @config.dup
        config[:network_object_groups]['datacenter1'].push({:wildcard_mask => '1.1.1.1'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_network_object_groups_wildcard_mask_invalid_error
        config = @config.dup
        config[:network_object_groups]['datacenter1'].push({:ip => '1.1.1.1', :wildcard_mask => '1.1.1.1.1'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    # acls
    def test_arg_acl_structure
        config = @config.dup
        config[:acls] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config = @config.dup
        config[:acls]['deny all'] = {}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:acls]['deny all'] = [[],[]]
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:acls]['deny all'] = [{:permission => 'deny', :ip => 'any'}]
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    def test_arg_acl_ip_format_error
        config = @config.dup
        config[:acls]['deny local'].push({:permission => :permit, :ip => '1.1.1.1.1'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_acl_wildcard_mask_format_error
        config = @config.dup
        config[:acls]['deny local'].push({:permission => :permit, :ip => '1.1.1.1', :wildcard_mask => '2555.255.255.0'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_acl_permission_not_permit_or_deny_error
        config = @config.dup
        config[:acls]['deny local'].push({:permission => 'a', :ip => '1.1.1.1'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_acl_missing_ip_error
        config = @config.dup
        config[:acls]['deny local'].push({:permission => :permit})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_acl_network_object_group_not_found_error
        config = @config.dup
        config[:acls]['deny local'].push({:permission => :permit, :network_object_group => 'dontexist'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    # command authorization profiles
    def test_arg_command_authorization_profile_structure
        config = @config.dup
        config[:command_authorization_profiles] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config = @config.dup
        config[:command_authorization_profiles]['profile1'] = {}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:command_authorization_profiles]['profile1'] = [[],[]]
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:command_authorization_profiles]['profile1'] = [{:acl => 'permit all', :shell_command_object_group => 'show commands'}]
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    def test_arg_command_authorization_profile_command_not_string_error
        config = @config.dup
        config[:command_authorization_profiles]['profile1'].push({:acl => 'permit all', :command => 1})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_command_authorization_profile_acl_not_found_error
        config = @config.dup
        config[:command_authorization_profiles]['profile1'].push({:acl => 'dontexist', :command => 'test'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_command_authorization_profile_shell_command_object_group_not_found_error
        config = @config.dup
        config[:command_authorization_profiles]['profile1'].push({:acl => 'permit all', :shell_command_object_group => 'dontexist', })
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end


    # command authorization whitelist
    def test_arg_command_authorization_whitelist
        config = @config.dup
        config[:command_authorization_whitelist] = {}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:command_authorization_whitelist] = [{}]
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:command_authorization_whitelist] = [{:acl => 'permit all', :shell_command_object_group => 'show commands'}]
        assert_nothing_raised(Exception){TacacsPlus::Server.new(@config)}
    end

    def test_arg_command_authorization_whitelist_command_not_string_error
        config = @config.dup
        config[:command_authorization_whitelist].push({:acl => 'permit all', :command => 1})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_command_authorization_whitelist_acl_not_found_error
        config = @config.dup
        config[:command_authorization_whitelist].push({:acl => 'dontexist', :command => 'test'})
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_command_authorization_whitelist_shell_command_object_group_not_found_error
        config = @config.dup
        config[:command_authorization_whitelist].push({:acl => 'permit all', :shell_command_object_group => 'dontexist', })
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end


    # author_avpairs
    def test_author_avpair_structure
        config = @config.dup
        config[:author_avpairs] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config = @config.dup
        config[:author_avpairs]['author_avpair1'] = {}
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:author_avpairs]['author_avpair1'] = [[],[]]
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:author_avpairs]['author_avpair1'] = [ {:acl => 'permit dc', :avpairs => ['idletime=5']} ]
    end

    def test_author_avpair_acl_not_found_error
        config = @config.dup
        config[:author_avpairs]['author_avpair1'][0][:acl] = 'unknown'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_author_avpair_avpair_too_long_error
        config = @config.dup
        config[:author_avpairs]['author_avpair1'][0][:avpairs].push('attr=' + 'a'*255)
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_author_avpair_avpair_invalid_error
        config = @config.dup
        config[:author_avpairs]['author_avpair1'][0][:avpairs].push('invalid')
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_author_avpair_service_invalid_error
        config = @config.dup
        config[:author_avpairs]['author_avpair1'][0][:service] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end


    # users
    def test_arg_users_structure
        config = @config.dup
        config[:users] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config = @config.dup
        config[:users]['dustin'] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_option_error
        config = @config.dup
        config[:users]['dustin'][:option] = true
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_command_authorization_profile_error
        config = @config.dup
        config[:users]['dustin'][:command_authorization_profile] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_disabled_option_error
        config = @config.dup
        config[:users]['dustin'][:disabled] = 'true'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_enable_not_string_error
        config = @config.dup
        config[:users]['dustin'][:enable] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_enable_too_long_error
        config = @config.dup
        config[:users]['dustin'][:enable] = 'a'*256
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_enable_hash_wrong_size_error
        config = @config.dup
        config[:users]['dustin'][:encryption] = 'sha1'
        config[:users]['dustin'][:enable] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_enable_acl_error
        config = @config.dup
        config[:users]['dustin'][:enable_acl] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_enable_expires_on_option_error
        config = @config.dup
        config[:users]['dustin'][:enable_expires_on] = 'date'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_encryption_unknown_type_error
        config = @config.dup
        config[:users]['dustin'][:encryption] = 'des'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_login_acl_error
        config = @config.dup
        config[:users]['dustin'][:login_acl] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_password_not_string_error
        config = @config.dup
        config[:users]['dustin'][:password] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_password_too_long_error
        config = @config.dup
        config[:users]['dustin'][:password] = 'a'*256
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_password_hash_wrong_size_error
        config = @config.dup
        config[:users]['dustin'][:encryption] = 'sha1'
        config[:users]['dustin'][:password] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_password_expires_on_option_error
        config = @config.dup
        config[:users]['dustin'][:password_expires_on] = 'date'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_salt_not_string_error
        config = @config.dup
        config[:users]['dustin'][:salt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_author_avpair_error
        config = @config.dup
        config[:users]['dustin'][:author_avpair] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_unknown_user_group_error
        config = @config.dup
        config[:users]['dustin'][:user_group] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    # user groups
    def test_arg_user_groups_structure
        config = @config.dup
        config[:user_groups] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config = @config.dup
        config[:user_groups]['group1'] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_unknown_option_error
        config = @config.dup
        config[:user_groups]['group1'][:option] = true
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_unknown_command_authorization_profile_error
        config = @config.dup
        config[:user_groups]['group1'][:command_authorization_profile] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_enable_not_string_error
        config = @config.dup
        config[:user_groups]['group1'][:enable] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_enable_too_long_error
        config = @config.dup
        config[:user_groups]['group1'][:enable] = 'a'*256
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_enable_hash_wrong_size_error
        config = @config.dup
        config[:user_groups]['group1'][:encryption] = 'sha1'
        config[:user_groups]['group1'][:enable] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_unknown_enable_acl_error
        config = @config.dup
        config[:user_groups]['group1'][:enable_acl] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_users_salt_not_string_error
        config = @config.dup
        config[:user_groups]['group1'][:salt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_salt_not_string_error
        config = @config.dup
        config[:user_groups]['group1'][:salt] =  1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_user_groups_unknown_author_avpair_error
        config = @config.dup
        config[:user_groups]['group1'][:author_avpair] = 'noexist'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    # tacacs daemon
    def test_arg_tacacs_daemon_structure
        config = @config.dup
        config[:tacacs_daemon] = []
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_daemon_unknown_option_error
        config = @config.dup
        config[:tacacs_daemon][:option] = true
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_daemon_default_policy_not_permit_or_deny_error
        config = @config.dup
        config[:tacacs_daemon][:default_policy] = 'a'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_daemon_disabled_prompt_not_string_error
        config = @config.dup
        config[:tacacs_daemon][:disabled_prompt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_daemon_dump_file_not_io_error
        config = @config.dup
        config[:tacacs_daemon][:dump_file] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_ip_invalid_error
        config = @config.dup
        config[:tacacs_daemon][:ip] = '1.1.1.1.1'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_daemon_key_not_string_error
        config = @config.dup
        config[:tacacs_daemon][:key] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_config_missing_key_with_testing_on
        config = @config.dup
        config[:tacacs_daemon].delete(:key)
        config[:tacacs_daemon][:testing] = true
        assert_nothing_raised(Exception){server = TacacsPlus::Server.new(config)}
    end

    def test_config_missing_key_with_testing_off
        config = @config.dup
        config[:tacacs_daemon].delete(:key)
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_log_aaa
        config = @config.dup
        config[:tacacs_daemon][:log_accounting] = false
        config[:tacacs_daemon][:log_authentication] = false
        config[:tacacs_daemon][:log_authorization] = false
        assert_nothing_raised(Exception){server = TacacsPlus::Server.new(config)}
        config[:tacacs_daemon][:log_accounting] = true
        config[:tacacs_daemon][:log_authentication] = true
        config[:tacacs_daemon][:log_authorization] = true
        assert_nothing_raised(Exception){server = TacacsPlus::Server.new(config)}
        config[:tacacs_daemon][:log_accounting] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:tacacs_daemon][:log_authentication] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
        config[:tacacs_daemon][:log_authorization] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_login_prompt_not_string_error
        config = @config.dup
        config[:tacacs_daemon][:login_prompt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_max_clients_not_int_error
        config = @config.dup
        config[:tacacs_daemon][:max_clients] = '1'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_name_not_str_error
        config = @config.dup
        config[:tacacs_daemon][:name] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_password_expired_prompt_not_string_error
        config = @config.dup
        config[:tacacs_daemon][:password_expired_prompt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_password_prompt_not_string_error
        config = @config.dup
        config[:tacacs_daemon][:password_prompt] = 1
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_port_not_integer_error
        config = @config.dup
        config[:tacacs_daemon][:port] = '1'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_port_invalid_error
        config = @config.dup
        config[:tacacs_daemon][:port] = 65536
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_sock_timeout_not_integer_error
        config = @config.dup
        config[:tacacs_daemon][:sock_timeout] = '1'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

    def test_arg_tacacs_testing_not_t_or_f_error
        config = @config.dup
        config[:tacacs_daemon][:testing] = '1'
        assert_raise(ArgumentError){TacacsPlus::Server.new(config)}
    end

end

__END__
