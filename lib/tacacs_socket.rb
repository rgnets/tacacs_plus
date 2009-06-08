module TacacsPlus

module TacacsSocket #:nodoc: all

# PRIVATE INSTANCE METHODS
private

#==============================================================================#
# get_packet()
#==============================================================================#

#===Synopsis
#Receive and decode an inbound TACACS+ packet from a TCPSocket.
#
#===Usage
# packet = get_packet(socket)
#
#===Arguments:
#* TCP Socket
#
#===Returns:
#* PacketStruct
#
    def get_packet(socket,key=nil)
        decoded = nil
        begin
            # this check exists for offline testing with TestIO
            if ( socket.kind_of?(IO) )
                # read from socket. decode only if we actually read something.
                if ( IO::select( [socket], nil, nil, @sock_timeout ) )
                    header = TacacsPlus::TacacsHeader.new( socket.readpartial(12) )
                    body = ''
                    remaining = header.length
                    while(remaining > 0)
                        body << socket.readpartial(remaining)
                        remaining = header.length - body.length
                    end

                    decoded = TacacsPlus.decode_packet(header,body,key)
                    if (@dump_file)
                        @dump_file.print("# Received\n" + decoded.to_yaml + "\n")
                        @dump_file.flush
                    end
                else
                    raise TimeoutError
                end
            else # assume offline testing with TestIO
                pkt = socket.read()
                raise(EOFError) if (pkt.nil?)
                header = TacacsPlus::TacacsHeader.new( pkt.slice!(0..11) )
                body =  pkt
                decoded = TacacsPlus.decode_packet(header,body,key)
            end

        rescue TimeoutError
            raise "Peer connection timed out."
        rescue EOFError
            raise "Peer sent EOF."
        rescue DecodeError => error
            raise "Error decoding data received from peer: #{error}"
        rescue Exception => error
            raise "Undefined error: #{error}."
        end

        return(decoded)
    end

#==============================================================================#
# send_packet()
#==============================================================================#

#===Synopsis
#Send TACACS+ packet to a TCPSocket.
#
#===Usage
# send_packet(socket,header,body)
#
#===Arguments:
#* TCP Socket
#* TacacsHeader
#* TacacsBody
#
#===Returns:
#* True
#
    def send_packet(socket,packet,key=nil)
        # set correct type
        if (packet.body.kind_of?(Authentication))
            packet.header.type_authentication!
        elsif (packet.body.kind_of?(Authorization))
            packet.header.type_authorization!
        else
            packet.header.type_accounting!
        end

        # set body & header length fields
        packet.body.set_len!
        packet.header.length = packet.body.packed.length

        if (@dump_file)
            @dump_file.print("# Sent\n" + packet.to_yaml + "\n")
            @dump_file.flush
        end
        pkt = TacacsPlus.encode_packet(packet,key)
        socket.write(pkt)
        return(true)
    end

end # module TacacsSocket

end # module TacacsPlus
