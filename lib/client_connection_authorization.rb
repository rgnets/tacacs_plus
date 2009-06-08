module TacacsPlus


class ClientConnection
private

#==============================================================================#
# author_shell_command()
#==============================================================================#

# process authorization when service = shell and cmd != ''
#
    def author_shell_command(new_body,username,avpairs,author_request)
        # set pass/fail based on default policy. we may change this
        # setting below depending whether or not a command_authorization_profile
        # is configured
        loglevel = :warn # specify this so that whitelist commands may be logged at a higher level
        message = ''
        whitelisted = false

        # get all cmd-arg entries
        command = []
        avpairs.each do |avpair|
            # look for 'cmd-arg' to append to command
            command.push(avpair[:value]) if (avpair[:attribute] == 'cmd' || avpair[:attribute] == 'cmd-arg')
        end
        command = command.join(' ')


        # check whitelist
        if (@tacacs_daemon.command_authorization_whitelist)
            @tacacs_daemon.command_authorization_whitelist.each do |entry|
                rule = entry.match?(@peeraddr,command)
                if (rule)
                    whitelisted = true
                    new_body.status_passadd!
                    message = "User permitted by whitelisted rule: #{rule}."
                    loglevel = :info
                    break
                end
            end
        end


        # if no whitelist match
        if (!whitelisted)
            user = @tacacs_daemon.users(username) if (username)
            # fail if user unknown
            if (!user)
                new_body.status_fail!
                message = "Authorization attempt from unknown user."

            # fail if user account disabled
            elsif (user.disabled?)
                new_body.status_fail!
                message = "Authorization attempt from disabled account."

            else
                # get user command auth profile if one exists
                command_auth_profile = nil
                if (user.command_authorization_profile)
                    command_auth_profile = user.command_authorization_profile

                # if not present, then get group command auth profile if one exists
                elsif(user.user_group )
                    if (user.user_group.command_authorization_profile)
                        command_auth_profile =  user.user_group.command_authorization_profile
                    end
                end

                # check command_auth_profile if any
                if (command_auth_profile)
                    match_results = command_auth_profile.matching_entry(command,@peeraddr)
                    if (match_results)
                        if (match_results[:permit])
                            new_body.status_passadd!
                            if ( match_results.has_key?(:by) )
                                message = "User permitted by #{match_results[:by]} on rule: #{match_results[:rule]}."
                            else
                                message = "User permitted by rule: #{match_results[:rule]}."
                            end
                        else
                            new_body.status_fail!
                            message = "User denied by #{match_results[:by]} on rule: #{match_results[:rule]}."
                        end
                    else
                        new_body.status_fail!
                        message = "Authorization denied due to implicit deny."
                    end

                elsif (@tacacs_daemon.default_policy == :deny)
                    new_body.status_fail!
                    message = "Authorization denied due to default policy."

                else
                    new_body.status_passadd!
                    message = "Authorization permitted due to default policy."
                end
            end
        end

        # log this attempt
        @tacacs_daemon.log(loglevel,['msg_type=Authorization', "message=#{message}", "command=#{command}", "status=#{new_body.xlate_status}"],author_request,@peeraddr)

        return(nil)
    end

#==============================================================================#
# issue_settings()
#==============================================================================#

# issue avpairs representing shell settings
#
    def issue_settings(new_body, username, service, author_request)
        # fail if user unknown
        user = @tacacs_daemon.users(username) if (username)
        if (!user)
            new_body.status_fail!
            @tacacs_daemon.log(:warn,['msg_type=Authorization', "message=Authorization attempt from unknown user.", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
            return(nil)

        # fail if user account disabled
        elsif (user.disabled?)
            new_body.status_fail!
            @tacacs_daemon.log(:warn,['msg_type=Authorization', "message=Authorization attempt from disabled account.", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
            return(nil)

        elsif (user.author_avpair)
            author_avpair = user.author_avpair

        elsif (user.user_group && user.user_group.author_avpair)
            author_avpair = user.user_group.author_avpair
        end

        args = author_avpair.matching_entry(service,@peeraddr) if (author_avpair)

        if (args)
            new_body.status_passadd!
            new_body.args = args
            @tacacs_daemon.log(:info,['msg_type=Authorization', "message=User issued the following AVPairs: #{new_body.args.join(', ')}", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
        else
            new_body.status_fail!
            @tacacs_daemon.log(:debug,['msg_type=Authorization', "message=No AVPairs could be issued for service '#{service}'", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
        end

        return(nil)
    end


#==============================================================================#
# process_authorization()
#==============================================================================#

# the main handler for authorization messages
#
    def process_authorization(session)
        author_request = session.author_request
        new_body = TacacsPlus::AuthorizationResponse.new
        username = session.author_request.body.user

        # fail if version unsupported
        if (author_request.header.version != 0xc0)
                msg = "Client version of TACACS+ (0x#{author_request.header.version.to_s(16)}) is unsupported."
                @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', "message=#{msg}"],author_request,@peeraddr)
                author_request.header.version = 0xc0
                new_body.status_error!
                new_body.server_msg = msg

        # else process shell command authorization
        elsif (author_request.body.args)
            # validate avpairs
            av_error = nil
            service = nil
            cmd = nil
            args = []
            begin
                # some clients wrongly send blank as the first arg, so we need to ignore them.
                av = nil
                while(1)
                    av = TacacsPlus.validate_avpair(author_request.body.args.shift)
                    break if (av[:attribute] != '')
                end

                # first arg should be 'service'.
                if (av[:attribute] != 'service')
                    raise "Attribute 'service' is required to be the first argument for authorization requests."
                else
                    service = av[:value]
                end

                # check the remaining args
                author_request.body.args.each do |arg|
                    av = TacacsPlus.validate_avpair(arg)
                    cmd = av[:value] if (av[:attribute] == 'cmd')
                    args.push(av)
                end
            rescue Exception => av_error
                msg = "AVPair provided by client raised the following error: #{av_error}"
                new_body.status_fail!
                new_body.data = msg
                @tacacs_daemon.log(:debug,['msg_type=Authorization', "message=#{msg}", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
            end

            if (!av_error)
                if (service == 'shell')
                    if (cmd)
                        # if cmd= '' then issue shell settings, otherwise authorize command
                        if (cmd != '')
                            author_shell_command(new_body,username,args,author_request)
                        else
                            issue_settings(new_body, username, service, author_request)
                        end

                    else
                        msg = "Attribute 'cmd' is required when service is 'shell'."
                        new_body.status_fail!
                        new_body.data = msg
                        @tacacs_daemon.log(:error,['msg_type=Authorization', "message=#{msg}", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
                    end

                else # assume that we need to issue settings for the provided service
                    issue_settings(new_body, username, service, author_request)
                end
            end

        else
            msg = "No arguments were provided with authorization request."
            new_body.status_fail!
            new_body.data = msg
            @tacacs_daemon.log(:error,['msg_type=Authorization', "message=#{msg}", "status=#{new_body.xlate_status}"],author_request,@peeraddr)
        end

        # finish up
        session.reply.header = author_request.header.dup
        session.reply.body = new_body
        session.terminate = true
        return(nil)
    end



end # class ClientConnection


end # module TacacsPlus

__END__
