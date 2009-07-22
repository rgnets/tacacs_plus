module TacacsPlus


class ClientConnection
private


#==============================================================================#
# ascii_login_and_enable()
#==============================================================================#

# code for doing an ascii login and enable
#
    def ascii_login_and_enable(session,new_body)
        authen_start = session.authen_start
        authen_cont = session.authen_cont

        if (!session.reply.body) # no previous conversation has taken place
            if (authen_start.body.user_len == 0)
                # request username
                new_body.status_getuser!
                new_body.server_msg = @tacacs_daemon.login_prompt
            else
                # request password
                session.getuser = authen_start.body.user
                new_body.status_getpass!
                new_body.flag_noecho!
                new_body.server_msg = @tacacs_daemon.password_prompt
            end

        else # make sure we got what we asked for in last reply
            if (session.reply.body.status_getuser?)
                if (authen_cont.body.user_msg_len != 0)
                    # request password
                    session.getuser = authen_cont.body.user_msg
                    new_body.status_getpass!
                    new_body.flag_noecho!
                    new_body.server_msg = @tacacs_daemon.password_prompt

                else
                    # fail
                    new_body.status_fail!
                    new_body.server_msg = "Username requested but none provided."
                end

            elsif (session.reply.body.status_getpass?)
                if (authen_cont.body.user_msg_len != 0)
                    # determine pass/fail status
                    username = session.getuser
                    password = authen_cont.body.user_msg
                    pass_fail = authenticate(username, password, session.authen_start)

                    # set reply based on pass_fail
                    if (pass_fail[:pass])
                        new_body.status_pass!
                    else
                        new_body.status_fail!
                        new_body.server_msg = pass_fail[:msg]
                    end

                else
                    # fail
                    new_body.status_fail!
                    new_body.server_msg = "Password requested but none provided."
                end

            else
                # all other statuses are in error, so some sort of internal error must have occured
                new_body.status_error!
                new_body.server_msg = "Internal Server Error. Unexpected status for ASCII login/enable: #{session.reply.body.status}"
                @tacacs_daemon.log(:erro,['msg_type=Authentication', "message=#{new_body.server_msg}", "status=#{new_body.xlate_status}"],authen_start,@peeraddr)

            end
        end

        return(nil)
    end

#==============================================================================#
# authen_action_chpass()
#==============================================================================#

# code for doing ascii change password requests only
#
    def authen_action_chpass(session,new_body)
        authen_start = session.authen_start
        authen_cont = session.authen_cont

        # make sure this is an ascii or enable request
        if (!authen_start.body.authen_type_ascii? && !authen_start.body.service_enable?)
            new_body.status_fail!
            new_body.server_msg = "Only ascii password change requests are supported."
            return(nil)
        end

        if (!session.reply.body) # no previous conversation has taken place
            if (authen_start.body.user_len == 0)
                # request username
                new_body.status_getuser!
                new_body.server_msg = @tacacs_daemon.login_prompt
            else
                # request old password
                session.getuser = authen_start.body.user
                new_body.status_getdata!
                new_body.flag_noecho!
                new_body.server_msg = @tacacs_daemon.password_prompt
            end

        else # make sure we got what we asked for in last reply
            if (session.reply.body.status_getuser?)
                if (authen_cont.body.user_msg_len != 0)
                    # request old password
                    session.getuser = authen_cont.body.user_msg
                    new_body.status_getdata!
                    new_body.flag_noecho!
                    new_body.server_msg = @tacacs_daemon.password_prompt

                else
                    # fail
                    new_body.status_fail!
                    new_body.server_msg = "Username requested but none provided."
                end

            elsif (session.reply.body.status_getdata?)
                if (authen_cont.body.user_msg_len != 0)
                    # determine pass/fail status
                    username = session.getuser
                    password = authen_cont.body.user_msg

                    pass_fail = authenticate(username, password, session.authen_start)

                    if (pass_fail[:pass])
                        new_body.status_getpass!
                        new_body.flag_noecho!
                        new_body.server_msg = "New Password: "
                    else
                        new_body.status_fail!
                        new_body.server_msg = pass_fail[:msg]
                    end

                else
                    # fail
                    new_body.status_fail!
                    new_ body.server_msg = "Password requested but none provided."
                end

            elsif (session.reply.body.status_getpass?)
                if (authen_cont.body.user_msg_len != 0)
                    # determine pass/fail status
                    username = session.getuser
                    password = authen_cont.body.user_msg

                    if (!session.getpass)
                        session.getpass = password
                        new_body.status_getpass!
                        new_body.flag_noecho!
                        new_body.server_msg = "Verify Password: "
                    else
                        if (session.getpass == password)
                            user = @tacacs_daemon.users(username) if (username)

                            if (session.authen_start.body.service_enable?)
                                user.enable_password = password
                            else
                                user.login_password = password
                            end
                            new_body.status_pass!
                            new_body.server_msg = "Password updated."
                            @tacacs_daemon.log(:info, ['msg_type=Authentication', 'message=Password has been updated.', "status=#{new_body.xlate_status}"],authen_start,@peeraddr,username)
                        else
                            new_body.status_fail!
                            new_body.server_msg = "Passwords did not match."
                        end

                    end

                else
                    # fail
                    new_body.status_fail!
                    new_ body.msg = "Password requested but none provided."
                end

            else
                # all other statuses are in error, so some sort of internal error must have occured
                new_body.status_error!
                new_body.server_msg = "Internal Server Error. Unexpected status for ASCII change " +
                                      "password request: #{session.reply.body.status}"
                @tacacs_daemon.log(:error, ['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
            end
        end

        return(nil)
    end

#==============================================================================#
# authen_action_login()
#==============================================================================#

# process authen start messages where action=login
#
    def authen_action_login(session,new_body)
        authen_start = session.authen_start

        # process authen_type
        if (authen_start.body.authen_type_ascii? || authen_start.body.service_enable?)
            ascii_login_and_enable(session,new_body)
        elsif (authen_start.body.authen_type_pap?)
            pap_login(session,new_body)
        elsif (authen_start.body.authen_type_chap?)
            chap_login(session,new_body)
        elsif (authen_start.body.authen_type_arap?)
            new_body.status_fail!
            new_body.server_msg = "ARAP is currently unsupported."
        elsif (authen_start.body.authen_type_mschap?)
            new_body.status_fail!
            new_body.server_msg = "MS-CHAP is currently unsupported."
        else
            new_body.status_fail!
            new_body.server_msg = "Client requested unknown or unsupported authen_type: #{authen_start.body.authen_type} (is client using correct encryption key?)"
            @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        end

        return(nil)
    end

#==============================================================================#
# authenticate()
#==============================================================================#

# authenticate a login or enable password
#
    def authenticate(username,password,authen_start)
        acl = nil
        enable = authen_start.body.service_enable?
        ret_val = {:pass => false, :msg => "Username or password incorrect."}
        ret_val[:msg] = "Password incorrect." if (enable)
        fail_log_msg = "Authentication failed."
        user = @tacacs_daemon.users(username) if (username)

        # check for active account, and valid pw
        if (!user) # fail if user unknown
            fail_log_msg += " Unknown user."

        elsif (enable) # check enable password
            if (user.enable_password)
                if ( user.verify_enable_password(password) )
                   if (!user.disabled?)
                      ret_val[:pass] = true
                      # if login, check if enable is expired
                      if (authen_start.body.action_login? && user.enable_password_expired?)
                          ret_val[:pass] = false
                          ret_val[:msg] = @tacacs_daemon.password_expired_prompt
                          fail_log_msg += " Enable password expired."
                      end
                   else
                      ret_val[:msg] = @tacacs_daemon.disabled_prompt
                      fail_log_msg += " Account disabled."
                   end

                end

                # get acl for enable access. always prefer one set on user over one set on group
                if (user.enable_acl)
                    acl = user.enable_acl
                elsif (user.user_group)
                    acl = user.user_group.enable_acl
                end

            end

        elsif(user.login_password) # check login password
            if ( user.verify_login_password(password) )
                if (!user.disabled?)
                      ret_val[:pass] = true
                      # if login, check if password is expired
                      if (authen_start.body.action_login? && user.login_password_expired?)
                          ret_val[:pass] = false
                          ret_val[:msg] = @tacacs_daemon.password_expired_prompt
                          fail_log_msg += " Login password expired."
                      end
                   else
                      ret_val[:msg] = @tacacs_daemon.disabled_prompt
                      fail_log_msg += " Account disabled."
                   end

            end

            # get acl for login access. always prefer one set on user over one set on group
            if (user.login_acl)
                acl = user.login_acl
            elsif (user.user_group)
                acl = user.user_group.login_acl
            end
        end

        # if active account and password correct, then check acl. else log failure
        if (ret_val[:pass])
            if (acl)
                match_results = acl.match(@peeraddr)

                if ( match_results[:permit] )
                    pass_log_msg = "Authentication successful. User permitted by ACL '#{acl.name}' #{match_results[:by]}."
                else
                    ret_val[:pass] = false
                    ret_val[:msg] = "Authentication denied due to ACL restrictions on user."
                    fail_log_msg += " User denied by ACL '#{acl.name}' #{match_results[:by]}."
                end
            else
                pass_log_msg = "Authentication successful."
            end
        end

        # log pass/fail
        if (ret_val[:pass])
            if (enable)
                @tacacs_daemon.log(:info,['msg_type=Authentication', "message=#{pass_log_msg}","status=Pass"],authen_start,@peeraddr, username)
            else
                @tacacs_daemon.log(:warn,['msg_type=Authentication', "message=#{pass_log_msg}","status=Pass"],authen_start,@peeraddr, username)
            end
        else
            @tacacs_daemon.log(:warn,['msg_type=Authentication', "message=#{fail_log_msg}","status=Fail"],authen_start,@peeraddr, username)
        end


        return(ret_val)
    end


#==============================================================================#
# chap_login()
#==============================================================================#

# code for doing a chap login
#
    def chap_login(session,new_body)
        authen_start = session.authen_start
        new_body.server_msg = "Username or password incorrect."

        if (!authen_start.header.minor_version_one?) # requires minor version 1
            new_body.status_fail!
            new_body.server_msg = "Client sent malformed packet to server for CHAP login. " +
                                  "Minor version in TACACS+ header should be 1 but was #{authen_start.header.minor_version}."
            @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        elsif (authen_start.body.user_len != 0 && authen_start.body.data_len != 0)
            # get ppp_id, challenge, and response. ppp_id = 1 octet, response = 16 octets, challenge = remainder
            challenge_len = authen_start.body.data_len - 17
            ppp_id = authen_start.body.data[0].chr
            challenge = authen_start.body.data[1,challenge_len]
            response = authen_start.body.data[challenge_len+1, authen_start.body.data_len-1]

            username = authen_start.body.user
            user = @tacacs_daemon.users(username) if (username)
            if (user && user.login_password)
                if (Digest::MD5.digest(ppp_id + user.login_password + challenge) == response)
                    if (user.login_password_expired?)
                        new_body.status_fail!
                        new_body.server_msg = @tacacs_daemon.password_expired_prompt
                    elsif (user.login_acl)
                        match_results = user.login_acl.match(@peeraddr)
                        if ( match_results[:permit] )
                            new_body.status_pass!
                            new_body.server_msg = ""
                        else
                            new_body.status_fail!
                            new_body.server_msg = "Authentication denied due to ACL restrictions on user."
                            @tacacs_daemon.log(:info,['msg_type=Authentication', 'message=User attempted CHAP login to restricted device.',"status=#{new_body.xlate_status}"],authen_start,@peeraddr)
                        end

                    elsif (@tacacs_daemon.default_policy == :deny)
                        new_body.status_fail!
                        new_body.server_msg = "Authentication denied due to ACL restrictions on user."
                        @tacacs_daemon.log(:info,['msg_type=Authentication', 'message=CHAP login denied due to default policy.',"status=#{new_body.xlate_status}"],authen_start,@peeraddr)

                    else
                        @tacacs_daemon.log(:info,['msg_type=Authentication', 'message=CHAP login permitted due to default policy.',"status=#{new_body.xlate_status}"],authen_start,@peeraddr)
                        new_body.status_pass!
                        new_body.server_msg = ""
                    end
                else
                    new_body.status_fail!
                end
            else
                new_body.status_fail!
            end

        else
            new_body.status_fail!
            new_body.server_msg = "Client requested CHAP login without providing both username and password."
            @tacacs_daemon.log(:warn,['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        end

        if (new_body.status_pass?)
            @tacacs_daemon.log(:warn,['msg_type=Authentication', 'message=Authentication successful.',"status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        end

        return(nil)
    end


#==============================================================================#
# pap_login()
#==============================================================================#

# code for doing a pap login
#
    def pap_login(session,new_body)
        authen_start = session.authen_start

        if (!authen_start.header.minor_version_one?) # pap login requires minor version 1
            new_body.status_fail!
            new_body.server_msg = "Client sent malformed packet to server for PAP login. " +
                                  "Minor version should be 1 but was #{authen_start.header.minor_version}."
            @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        elsif (authen_start.body.user_len != 0 && authen_start.body.data_len != 0)
            # determine pass/fail status
            username = authen_start.body.user
            pass_fail = authenticate(username, authen_start.body.data, authen_start)
            if (pass_fail[:pass])
                new_body.status_pass!
            else
                new_body.status_fail!
                new_body.server_msg = pass_fail[:msg]
            end

        else
            new_body.status_fail!
            new_body.server_msg = "Client requested PAP login without providing both username and password."
            @tacacs_daemon.log(:debug,['msg_type=Authentication', "message=#{new_body.server_msg}","status=#{new_body.xlate_status}"],authen_start,@peeraddr)
        end

        return(nil)
    end


#==============================================================================#
# process_authentication()
#==============================================================================#

# the main handler for authentication messages
#
    def process_authentication(session)
        authen_start = session.authen_start
        authen_cont = session.authen_cont
        new_header = nil
        new_body = TacacsPlus::AuthenticationReply.new

        # get header from most recently received packet and
        # do basic validations on the packet
        if (authen_cont)
            new_header = authen_cont.header.dup

            # this is the continuation of a conversation
            if (new_header.seq_no >= 253)
                # seq_no is too high
                new_body.status_fail!
                new_body.server_msg = "seq_no has reached maximum acceptable value of 253. Terminating session."
                @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}", "status=#{new_body.xlate_status}"],authen_start,@peeraddr)
            elsif (authen_cont.body.flag_abort?)
                # abort flag. dont send reply
                session.reply = nil
                return(nil)
            end

        else
            new_header = authen_start.header.dup
        end

        # process only if not already failed or otherwise terminated
        if (!new_body.status_fail?)
            if (new_header.version != 0xc0 && new_header.version != 0xc1)
                msg = "Client version of TACACS+ (0x#{new_header.version.to_s(16)}) is unsupported."
                @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', "message=#{msg}"],authen_start,@peeraddr)
                new_header.version = 0xc1
                new_body.status_error!
                new_body.server_msg = msg
            elsif (authen_start.body.action_login?)
                authen_action_login(session,new_body)
            elsif(authen_start.body.action_chpass?)
                authen_action_chpass(session,new_body)
            elsif(authen_start.body.action_sendpass?)
                new_body.status_error!
                new_body.server_msg = "Send Pass is depricated and unsupported."
                @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}", "status=#{new_body.xlate_status}"],authen_start,@peeraddr)
            elsif(authen_start.body.action_sendauth?)
                new_body.status_error!
                new_body.server_msg = "Send Auth is currently unsupported."
                @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}", "status=#{new_body.xlate_status}"],authen_start,@peeraddr)
            else
                new_body.status_error!
                new_body.server_msg = "Client requested unknown or unsupported action: #{authen_start.body.xlate_action} (is client using correct encryption key?)."
                @tacacs_daemon.log(:error,['msg_type=Authentication', "message=#{new_body.server_msg}", "status=#{new_body.xlate_status}"],authen_start,@peeraddr)
            end
        end

       # finish up
        if (!new_body.status_getuser? && !new_body.status_getpass? && !new_body.status_getdata?)
            session.terminate = true
        else
            session.expected_seq_no = session.expected_seq_no + 2
        end

        session.reply.header = new_header
        session.reply.body = new_body

        return(nil)
    end


end # class ClientConnection


end # module TacacsPlus

__END__
